from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta, timezone
import asyncpg
import secrets
import os
import json
from contextlib import asynccontextmanager

DATABASE_URL = os.getenv("DATABASE_URL")
DEFAULT_USERS_JSON = os.getenv("USERS", "[]")

# --- Models ---
class AuthRequest(BaseModel):
    codeword: str

class AuthResponse(BaseModel):
    token: str
    expires: datetime

class MessageIn(BaseModel):
    reply_to_message_id: Optional[int] = None
    message: str

class MessageOut(BaseModel):
    message_id: int
    reply_to_message_id: Optional[int]
    from_username: str
    from_is_human: bool
    reply_to_username: Optional[str]
    message: str
    datetime: datetime

# --- FastAPI with lifespan handler ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await asyncpg.create_pool(DATABASE_URL)

    async with app.state.pool.acquire() as conn:
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            codeword TEXT NOT NULL,
            is_human BOOLEAN DEFAULT TRUE
        );

        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            username TEXT REFERENCES users(username),
            expires TIMESTAMPTZ NOT NULL
        );

        CREATE TABLE IF NOT EXISTS messages (
            message_id SERIAL PRIMARY KEY,
            reply_to_message_id INTEGER,
            from_username TEXT NOT NULL REFERENCES users(username),
            reply_to_username TEXT,
            message TEXT NOT NULL,
            datetime TIMESTAMPTZ NOT NULL
        );
        """)

        try:
            parsed_users = json.loads(DEFAULT_USERS_JSON)
            for entry in parsed_users:
                username = entry["username"]
                codeword = entry["codeword"]
                is_human = entry.get("is_human", True)

                existing = await conn.fetchrow("SELECT codeword FROM users WHERE username=$1", username)
                if existing:
                    if existing["codeword"] != codeword:
                        await conn.execute("UPDATE users SET codeword=$1 WHERE username=$2", codeword, username)
                else:
                    await conn.execute(
                        "INSERT INTO users (username, codeword, is_human) VALUES ($1, $2, $3)",
                        username, codeword, is_human
                    )
        except Exception as e:
            print("[INIT USERS ERROR]", e)

    yield
    await app.state.pool.close()

app = FastAPI(lifespan=lifespan)

@app.get("/")
async def root():
    return {"status": "ok"}

@app.get("/ping")
async def ping():
    return {"pong": True, "time": datetime.now(timezone.utc).isoformat()}

# --- Auth Dependency ---
async def verify_token(authorization: Optional[str] = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization[7:]
    async with app.state.pool.acquire() as conn:
        row = await conn.fetchrow("SELECT username, expires FROM tokens WHERE token = $1", token)
        if not row or row["expires"] < datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        return row["username"]

# --- Auth ---
@app.post("/auth/{username}", response_model=AuthResponse)
async def authenticate(username: str, req: AuthRequest):
    async with app.state.pool.acquire() as conn:
        user = await conn.fetchrow("SELECT codeword FROM users WHERE username=$1", username)
        if not user or user["codeword"] != req.codeword:
            raise HTTPException(status_code=403, detail="Invalid codeword")
        token = secrets.token_hex(16)
        expires = datetime.now(timezone.utc) + timedelta(days=1)
        await conn.execute(
            "INSERT INTO tokens (token, username, expires) VALUES ($1, $2, $3)",
            token, username, expires
        )
        return {"token": token, "expires": expires}

# --- Send message ---
@app.post("/participants")
async def send_broadcast(msg: MessageIn, from_user: str = Depends(verify_token)):
    async with app.state.pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO messages (from_username, message, datetime, reply_to_message_id)
            VALUES ($1, $2, $3, $4)
            """,
            from_user, msg.message, datetime.now(timezone.utc), msg.reply_to_message_id
        )
        return {"status": "ok"}

@app.post("/participants/{to_user}")
async def send_direct(to_user: str, msg: MessageIn, from_user: str = Depends(verify_token)):
    async with app.state.pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO messages (from_username, reply_to_username, message, datetime, reply_to_message_id)
            VALUES ($1, $2, $3, $4, $5)
            """,
            from_user, to_user, msg.message, datetime.now(timezone.utc), msg.reply_to_message_id
        )
        return {"status": "ok"}

# --- Receive messages ---
@app.get("/messages", response_model=List[MessageOut])
async def get_all_messages(
    from_id: int = 0,
    from_user: Optional[str] = None,
    to_user: Optional[str] = None,
    limit: int = 100,
    auth_user: str = Depends(verify_token)
):
    conditions = ["m.message_id > $1"]
    params = [from_id]
    i = 2
    if from_user:
        conditions.append(f"m.from_username = ${i}")
        params.append(from_user)
        i += 1
    if to_user:
        conditions.append(f"m.reply_to_username = ${i}")
        params.append(to_user)
        i += 1
    conditions_str = " AND ".join(conditions)
    query = f"""
        SELECT m.message_id, m.reply_to_message_id, m.from_username, u.is_human AS from_is_human,
               m.reply_to_username, m.message, m.datetime
        FROM messages m
        JOIN users u ON u.username = m.from_username
        WHERE {conditions_str}
        ORDER BY m.message_id ASC
        LIMIT ${i}
    """
    params.append(limit)

    async with app.state.pool.acquire() as conn:
        rows = await conn.fetch(query, *params)
        return [dict(row) for row in rows]

@app.get("/participants", response_model=List[MessageOut])
async def get_broadcast(from_id: int = 0, username: str = Depends(verify_token)):
    async with app.state.pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT m.message_id, m.reply_to_message_id, m.from_username, u.is_human AS from_is_human,
                   m.reply_to_username, m.message, m.datetime
            FROM messages m
            JOIN users u ON u.username = m.from_username
            WHERE m.message_id > $1 AND (m.reply_to_username IS NULL OR m.reply_to_username = '')
            ORDER BY m.message_id ASC
            """, from_id
        )
        return [dict(row) for row in rows]

@app.get("/participants/{username}", response_model=List[MessageOut])
async def get_direct(username: str, from_id: int = 0, auth_user: str = Depends(verify_token)):
    if username != auth_user:
        raise HTTPException(status_code=403, detail="Can only request your own messages")
    async with app.state.pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT m.message_id, m.reply_to_message_id, m.from_username, u.is_human AS from_is_human,
                   m.reply_to_username, m.message, m.datetime
            FROM messages m
            JOIN users u ON u.username = m.from_username
            WHERE m.message_id > $1 AND m.reply_to_username = $2
            ORDER BY m.message_id ASC
            """, from_id, username
        )
        return [dict(row) for row in rows]