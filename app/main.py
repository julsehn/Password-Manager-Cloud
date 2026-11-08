"""Password Manager Cloud API - FastAPI Backend for Railway.

Official Cloud synchronization backend:
- Zero-knowledge storage: only stores encrypted blobs and user authentication credentials.
- Client-side encryption ensures user passwords are never known by the server.
"""
import os
import re
import sqlite3
import hashlib
import secrets
import time
from collections import defaultdict, deque
from contextlib import closing
from threading import Lock
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime, timedelta, timezone
from pathlib import Path
import jwt
from argon2 import PasswordHasher, exceptions as argon2_exceptions

# JWT & Security Configuration
SECRET_KEY = os.environ.get("SESSION_SECRET") or os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SESSION_SECRET must be configured before starting the cloud API")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 30
PASSWORD_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
AUTH_RATE_LIMIT = 10
AUTH_RATE_WINDOW_SECONDS = 900
_auth_attempts: dict[str, deque[float]] = defaultdict(deque)
_auth_attempts_lock = Lock()

# Database Configuration
raw_db_dir = os.environ.get("DB_DIR", "/data" if os.path.exists("/data") else ".")
DB_DIR = Path(raw_db_dir)
try:
    DB_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    DB_DIR = Path(".")
DB_PATH = DB_DIR / "vaults.db"

MAX_BLOB_BYTES = int(os.environ.get("MAX_BLOB_BYTES", str(10 * 1024 * 1024)))
VAULT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


def get_db_connection() -> sqlite3.Connection:
    """Get a database connection with WAL mode."""
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Initialize database tables with automatic migration."""
    with closing(get_db_connection()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                token_version INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vaults (
                vault_id TEXT PRIMARY KEY,
                user_id INTEGER,
                token_digest TEXT NOT NULL,
                blob TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL
            )
            """
        )
        # Check if user_id column exists
        cursor = conn.execute("PRAGMA table_info(vaults)")
        cols = [row["name"] for row in cursor.fetchall()]
        if "user_id" not in cols:
            conn.execute("ALTER TABLE vaults ADD COLUMN user_id INTEGER DEFAULT 1")
        user_cols = [row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "token_version" not in user_cols:
            conn.execute(
                "ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0"
            )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER
            )
            """
        )
        conn.commit()


# Run DB initialization
init_db()


def hash_password(password: str) -> str:
    """Hash account passwords with Argon2id."""
    return PASSWORD_HASHER.hash(password)


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Verify Argon2id account password hashes."""
    if stored_hash.startswith("$argon2id$"):
        try:
            return PASSWORD_HASHER.verify(stored_hash, plain_password)
        except argon2_exceptions.VerificationError:
            return False
    return False


def enforce_auth_rate_limit(key: str) -> None:
    now = time.monotonic()
    with _auth_attempts_lock:
        attempts = _auth_attempts[key]
        while attempts and now - attempts[0] >= AUTH_RATE_WINDOW_SECONDS:
            attempts.popleft()
        if len(attempts) >= AUTH_RATE_LIMIT:
            raise HTTPException(status_code=429, detail="Massa intents. Torna-ho a provar més tard.")
        attempts.append(now)

        for stale_key in [
            existing for existing, values in _auth_attempts.items()
            if not values or now - values[-1] >= AUTH_RATE_WINDOW_SECONDS
        ]:
            _auth_attempts.pop(stale_key, None)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(user_id: int) -> str:
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires_at = int(time.time()) + REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    with closing(get_db_connection()) as conn:
        conn.execute(
            "INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (token_hash, user_id, expires_at),
        )
        conn.commit()
    return token


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="El token ha caducat")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invàlid")


def get_user_by_username(username: str) -> Optional[dict]:
    with closing(get_db_connection()) as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[dict]:
    with closing(get_db_connection()) as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def compute_user_vault_id(user_id: int, username: str) -> str:
    """Compute default deterministic vault_id for user if none exists."""
    with closing(get_db_connection()) as conn:
        row = conn.execute("SELECT vault_id FROM vaults WHERE user_id = ? ORDER BY version DESC LIMIT 1", (user_id,)).fetchone()
        if row:
            return row["vault_id"]
    derived = hashlib.sha256(f"user_{user_id}_{username}".encode("utf-8")).hexdigest()[:24]
    return f"vault_{derived}"


# Storage Manager
class VaultStorage:
    def __init__(self):
        pass

    def get_vault_by_user_id(self, user_id: int) -> Optional[dict]:
        with closing(get_db_connection()) as conn:
            row = conn.execute("SELECT * FROM vaults WHERE user_id = ? ORDER BY version DESC LIMIT 1", (user_id,)).fetchone()
            if row:
                return dict(row)
            return None

    def get_vault_by_id(self, vault_id: str, user_id: Optional[int] = None) -> Optional[dict]:
        with closing(get_db_connection()) as conn:
            row = conn.execute("SELECT * FROM vaults WHERE vault_id = ?", (vault_id,)).fetchone()
            if not row:
                return None
            res = dict(row)
            if user_id is not None and res.get("user_id") and res["user_id"] != user_id:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No tens permís per accedir a aquesta caixa forta")
            return res

    def upsert_vault(self, vault_id: str, blob: str, user_id: int, expected_version: Optional[int] = None) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        token_digest = hashlib.sha256(secrets.token_bytes(32)).hexdigest()

        with closing(get_db_connection()) as conn:
            current = conn.execute("SELECT * FROM vaults WHERE vault_id = ?", (vault_id,)).fetchone()
            if current:
                curr_user = current["user_id"]
                if curr_user is not None and curr_user != user_id:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="La caixa forta pertany a un altre usuari")

                if expected_version is not None and current["version"] != expected_version:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=f"Conflicte de versió: s'esperava {expected_version}, es té {current['version']}"
                    )

                new_version = current["version"] + 1
                conn.execute(
                    "UPDATE vaults SET blob = ?, version = ?, updated_at = ?, user_id = ? WHERE vault_id = ?",
                    (blob, new_version, now, user_id, vault_id)
                )
                conn.commit()
                return {
                    "vault_id": vault_id,
                    "blob": blob,
                    "version": new_version,
                    "updated_at": now
                }
            else:
                conn.execute(
                    """
                    INSERT INTO vaults (vault_id, token_digest, blob, version, updated_at, user_id)
                    VALUES (?, ?, ?, 1, ?, ?)
                    """,
                    (vault_id, token_digest, blob, now, user_id)
                )
                conn.commit()
                return {
                    "vault_id": vault_id,
                    "blob": blob,
                    "version": 1,
                    "updated_at": now
                }

    def delete_vault(self, vault_id: str, user_id: int) -> bool:
        with closing(get_db_connection()) as conn:
            current = conn.execute("SELECT * FROM vaults WHERE vault_id = ?", (vault_id,)).fetchone()
            if not current:
                return False
            if current["user_id"] is not None and current["user_id"] != user_id:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No tens permís per eliminar aquesta caixa forta")
            conn.execute("DELETE FROM vaults WHERE vault_id = ?", (vault_id,))
            conn.commit()
            return True


vault_storage = VaultStorage()

# App Definition
app = FastAPI(
    title="Caixa Forta Cloud API",
    description="Oficial Railway Synchronization Backend - Zero-knowledge encrypted vault storage",
    version="1.1.0",
)

cors_origins = [
    origin.strip()
    for origin in os.environ.get("CORS_ORIGINS", "").split(",")
    if origin.strip()
]
if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> dict:
    """Validate Bearer JWT token and return authenticated user."""
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autenticació requerida (falta token Bearer)",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    payload = decode_token(token)
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token no vàlid")
    user = get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuari no trobat")
    if payload.get("ver") != user.get("token_version", 0):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sessió revocada")
    return user


def validate_vault_id(vault_id: str) -> str:
    if not VAULT_ID_PATTERN.fullmatch(vault_id):
        raise HTTPException(status_code=400, detail="Format d'identificador de caixa forta invàlid")
    return vault_id


def check_blob_size(blob: str) -> None:
    if len(blob.encode("utf-8")) > MAX_BLOB_BYTES:
        raise HTTPException(status_code=413, detail="La caixa forta encriptada és massa gran")


# Request & Response Models
class RegisterVaultRequest(BaseModel):
    vault_id: str = Field(..., min_length=1)
    blob: str = Field(...)
    token: Optional[str] = None


class GetVaultResponse(BaseModel):
    vault_id: str
    blob: str
    version: int
    updated_at: str


class VaultBlobRequest(BaseModel):
    blob: str = Field(...)
    expected_version: Optional[int] = Field(default=None, ge=0)


class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    email: Optional[EmailStr] = None


class UserLoginRequest(BaseModel):
    username: str = Field(...)
    password: str = Field(...)


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., min_length=32, max_length=256)


class UserResponse(BaseModel):
    user_id: int
    username: str
    email: Optional[str] = None
    access_token: str
    refresh_token: str
    vault_id: str
    token_type: str = "bearer"


# Routes
@app.get("/")
@app.get("/healthz")
async def health_check():
    """Health check endpoint for Railway and clients."""
    return {"status": "ok", "service": "Caixa Forta Cloud API (Railway)", "version": "1.1.0"}


@app.post("/v1/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(payload: UserRegisterRequest, http_request: Request):
    """Register a new user account on the official Railway cloud."""
    client_ip = http_request.client.host if http_request.client else "unknown"
    enforce_auth_rate_limit(f"register:{client_ip}")
    existing = get_user_by_username(payload.username)
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Aquest nom d'usuari ja existeix")

    now = datetime.now(timezone.utc).isoformat()
    p_hash = hash_password(payload.password)

    with closing(get_db_connection()) as conn:
        cursor = conn.execute(
            "INSERT INTO users (username, password_hash, email, created_at) VALUES (?, ?, ?, ?)",
            (payload.username, p_hash, payload.email, now),
        )
        conn.commit()
        user_id = cursor.lastrowid

    token = create_access_token(data={"sub": payload.username, "ver": 0})
    refresh_token = create_refresh_token(user_id)
    vault_id = compute_user_vault_id(user_id, payload.username)

    return UserResponse(
        user_id=user_id,
        username=payload.username,
        email=payload.email,
        access_token=token,
        refresh_token=refresh_token,
        vault_id=vault_id,
        token_type="bearer",
    )


@app.post("/v1/auth/login", response_model=UserResponse)
async def login_user(payload: UserLoginRequest, http_request: Request):
    """Authenticate with username and password, returning JWT access token."""
    client_ip = http_request.client.host if http_request.client else "unknown"
    enforce_auth_rate_limit(f"login:{client_ip}:{payload.username.casefold()}")
    user = get_user_by_username(payload.username)
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuari o contrasenya incorrectes")

    token = create_access_token(
        data={"sub": user["username"], "ver": user.get("token_version", 0)}
    )
    refresh_token = create_refresh_token(user["id"])
    vault_id = compute_user_vault_id(user["id"], user["username"])

    return UserResponse(
        user_id=user["id"],
        username=user["username"],
        email=user["email"],
        access_token=token,
        refresh_token=refresh_token,
        vault_id=vault_id,
        token_type="bearer",
    )


@app.post("/v1/auth/refresh", response_model=UserResponse)
async def refresh_access_token(payload: RefreshTokenRequest, http_request: Request):
    client_ip = http_request.client.host if http_request.client else "unknown"
    enforce_auth_rate_limit(f"refresh:{client_ip}")
    token_hash = hashlib.sha256(payload.refresh_token.encode("utf-8")).hexdigest()
    with closing(get_db_connection()) as conn:
        row = conn.execute(
            "SELECT * FROM refresh_tokens WHERE token_hash = ?", (token_hash,)
        ).fetchone()
    if not row or row["revoked_at"] is not None or row["expires_at"] <= int(time.time()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token invàlid")
    user = get_user_by_id(row["user_id"])
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuari no trobat")
    return UserResponse(
        user_id=user["id"],
        username=user["username"],
        email=user["email"],
        access_token=create_access_token(
            data={"sub": user["username"], "ver": user.get("token_version", 0)}
        ),
        refresh_token=payload.refresh_token,
        vault_id=compute_user_vault_id(user["id"], user["username"]),
        token_type="bearer",
    )


@app.post("/v1/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_refresh_token(payload: RefreshTokenRequest):
    token_hash = hashlib.sha256(payload.refresh_token.encode("utf-8")).hexdigest()
    now = int(time.time())
    with closing(get_db_connection()) as conn:
        row = conn.execute(
            "SELECT user_id FROM refresh_tokens WHERE token_hash = ?", (token_hash,)
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                (now, row["user_id"]),
            )
            conn.execute(
                "UPDATE users SET token_version = token_version + 1 WHERE id = ?",
                (row["user_id"],),
            )
            conn.commit()
    return None


@app.get("/v1/auth/me")
async def get_me(user: dict = Depends(get_current_user)):
    """Get current authenticated user info and associated vault."""
    vault_id = compute_user_vault_id(user["id"], user["username"])
    vault = vault_storage.get_vault_by_user_id(user["id"])
    return {
        "user_id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "vault_id": vault_id,
        "has_vault": vault is not None,
        "vault_version": vault["version"] if vault else 0,
        "updated_at": vault["updated_at"] if vault else None,
    }


# User-centric vault endpoints (no manual vault_id needed!)
@app.get("/v1/vault", response_model=GetVaultResponse)
async def get_my_vault(user: dict = Depends(get_current_user)):
    """Retrieve the current user's encrypted vault."""
    vault = vault_storage.get_vault_by_user_id(user["id"])
    if not vault:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Encara no hi ha cap caixa forta desada per aquest usuari")
    return GetVaultResponse(
        vault_id=vault["vault_id"],
        blob=vault["blob"],
        version=vault["version"],
        updated_at=vault["updated_at"],
    )


@app.put("/v1/vault", response_model=GetVaultResponse)
async def upload_my_vault(
    payload: VaultBlobRequest,
    user: dict = Depends(get_current_user),
):
    """Upload or sync the current user's encrypted vault."""
    check_blob_size(payload.blob)
    vault_id = compute_user_vault_id(user["id"], user["username"])
    vault = vault_storage.upsert_vault(
        vault_id=vault_id,
        blob=payload.blob,
        user_id=user["id"],
        expected_version=payload.expected_version,
    )
    return GetVaultResponse(
        vault_id=vault["vault_id"],
        blob=vault["blob"],
        version=vault["version"],
        updated_at=vault["updated_at"],
    )


# Explicit vault_id endpoints (backwards compatible)
@app.post("/v1/vaults", response_model=GetVaultResponse, status_code=status.HTTP_201_CREATED)
async def register_vault(
    request: RegisterVaultRequest,
    user: dict = Depends(get_current_user),
):
    """Register or initialize a vault with a specific ID."""
    v_id = validate_vault_id(request.vault_id)
    check_blob_size(request.blob)
    vault = vault_storage.upsert_vault(
        vault_id=v_id,
        blob=request.blob,
        user_id=user["id"],
        expected_version=None,
    )
    return GetVaultResponse(
        vault_id=vault["vault_id"],
        blob=vault["blob"],
        version=vault["version"],
        updated_at=vault["updated_at"],
    )


@app.get("/v1/vaults/{vault_id}", response_model=GetVaultResponse)
async def get_vault(
    vault_id: str,
    user: dict = Depends(get_current_user),
):
    """Download encrypted vault by ID."""
    v_id = validate_vault_id(vault_id)
    vault = vault_storage.get_vault_by_id(v_id, user_id=user["id"])
    if not vault:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Caixa forta no trobada")
    return GetVaultResponse(
        vault_id=vault["vault_id"],
        blob=vault["blob"],
        version=vault["version"],
        updated_at=vault["updated_at"],
    )


@app.put("/v1/vaults/{vault_id}", response_model=GetVaultResponse)
async def upload_vault(
    payload: VaultBlobRequest,
    vault_id: str,
    user: dict = Depends(get_current_user),
):
    """Upload or update encrypted vault by ID."""
    v_id = validate_vault_id(vault_id)
    check_blob_size(payload.blob)
    vault = vault_storage.upsert_vault(
        vault_id=v_id,
        blob=payload.blob,
        user_id=user["id"],
        expected_version=payload.expected_version,
    )
    return GetVaultResponse(
        vault_id=vault["vault_id"],
        blob=vault["blob"],
        version=vault["version"],
        updated_at=vault["updated_at"],
    )


@app.delete("/v1/vaults/{vault_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vault(
    vault_id: str,
    user: dict = Depends(get_current_user),
):
    """Delete a vault from Railway cloud."""
    v_id = validate_vault_id(vault_id)
    deleted = vault_storage.delete_vault(v_id, user["id"])
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Caixa forta no trobada")
    return None


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
