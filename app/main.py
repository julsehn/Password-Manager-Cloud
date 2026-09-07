"""Password Manager Cloud API - FastAPI Backend for Railway"""
import os
import sqlite3
import hashlib
import hmac
import base64
import secrets
import json
from contextlib import closing
from typing import Optional, Tuple
from fastapi import FastAPI, HTTPException, Depends, Header, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, EmailStr
from datetime import datetime, timedelta, timezone
from pathlib import Path
import jwt

# Add encryption utils
from app.utils.encryption import (
    serialize_vault,
    deserialize_vault,
    encrypt,
    decrypt,
    derive_key,
)
from app.models import VaultEntry

# JWT Configuration
SECRET_KEY = os.environ.get("SESSION_SECRET", secrets.token_hex(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

# Vault configuration
DB_DIR = Path(os.environ.get("DB_DIR", "/data"))
DB_PATH = DB_DIR / "vaults.db"
MAX_BLOB_BYTES = int(os.environ.get("MAX_BLOB_BYTES", str(10 * 1024 * 1024)))
VAULT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")



def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def verify_user(username: str, password: str) -> Optional[dict]:
    """Verify username/password and return user data if valid."""
    with closing(_get_connection()) as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE username = ? AND password_hash = ?",
            (username, hashlib.sha256(password.encode()).hexdigest()),
        ).fetchone()
        return row


class VaultStorage:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_connection(self):
        """Get a database connection with WAL mode for better concurrency."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        
        # Create tables if they don't exist
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS vaults (
                vault_id TEXT PRIMARY KEY,
                token_digest TEXT NOT NULL,
                blob TEXT NOT NULL,
                version INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                user_id TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        return connection


class VaultStorage:

    """Persistent SQLite storage for vaults with token-based authentication"""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_connection(self):
        """Get a database connection with WAL mode for better concurrency."""
        # Create parent directory if it doesn't exist
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        
        # Create tables if they don't exist
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS vaults (
                vault_id TEXT PRIMARY KEY,
                token_digest TEXT NOT NULL,
                blob TEXT NOT NULL,
                version INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        return connection

    def create_vault(self, vault_id: str, user_id: int, blob: str) -> dict:
        """Register a new vault"""
        if vault_id in self._vaults():
            raise HTTPException(status_code=409, detail="Vault already exists")

        now = datetime.now(timezone.utc).isoformat()
        user_digest = self._user_digest(user_id)

        with closing(self._get_connection()) as connection:
            connection.execute(
                """
                INSERT INTO vaults (vault_id, token_digest, blob, version, updated_at, user_id)
                VALUES (?, ?, ?, 1, ?, ?)
                """,
                (vault_id, user_digest, blob, now, user_id),
            )
            connection.commit()

        return {
            "vault_id": vault_id,
            "blob": blob,
            "version": 1,
            "updated_at": now,
        }

    def get_vault(self, vault_id: str, user_id: int) -> dict:
        """Get vault by ID with user verification"""
        if vault_id not in self._vaults():
            raise HTTPException(status_code=404, detail="Vault not found")

        user_digest = self._user_digest(user_id)

        with closing(self._get_connection()) as connection:
            row = connection.execute(
                "SELECT * FROM vaults WHERE vault_id = ?",
                (vault_id,),
            ).fetchone()

            if row is None or not hmac.compare_digest(row["token_digest"], user_digest) or row["user_id"] != user_id:
                raise HTTPException(status_code=404, detail="Vault not found")

            return {
                "vault_id": row["vault_id"],
                "blob": row["blob"],
                "version": row["version"],
                "updated_at": row["updated_at"],
            }

    def update_vault(self, vault_id: str, blob: str, user_id: int, expected_version: Optional[int] = None) -> dict:
        """Update vault with optimistic version checking"""
        if vault_id not in self._vaults():
            raise HTTPException(status_code=404, detail="Vault not found")

        current = self.get_vault(vault_id, user_id)

        # Version conflict check
        if expected_version is not None and current["version"] != expected_version:
            raise HTTPException(
                status_code=409,
                detail=f"Version conflict: expected {expected_version}, got {current['version']}"
            )

        now = datetime.now(timezone.utc).isoformat()

        with closing(self._get_connection()) as connection:
            connection.execute(
                """
                UPDATE vaults
                SET blob = ?, version = version + 1, updated_at = ?
                WHERE vault_id = ? AND user_id = ?
                """,
                (blob, now, vault_id, user_id),
            )
            connection.commit()

        # Get updated version
        with closing(self._get_connection()) as connection:
            row = connection.execute(
                "SELECT version FROM vaults WHERE vault_id = ?",
                (vault_id,),
            ).fetchone()
            new_version = row["version"]

        return {
            "vault_id": vault_id,
            "blob": blob,
            "version": new_version,
            "updated_at": now,
        }

    def delete_vault(self, vault_id: str, user_id: int) -> None:
        """Delete vault by ID"""
        if vault_id not in self._vaults():
            raise HTTPException(status_code=404, detail="Vault not found")

        with closing(self._get_connection()) as connection:
            connection.execute("DELETE FROM vaults WHERE vault_id = ? AND user_id = ?", (vault_id, user_id))
            connection.commit()

    def _vaults(self) -> dict:
        """Get all vault IDs (for checking existence)"""
        with closing(_get_connection()) as connection:
            rows = connection.execute("SELECT vault_id FROM vaults").fetchall()
            return {row["vault_id"] for row in rows}

    def _user_digest(self, user_id: int) -> str:
        """Create SHA256 digest of user_id for secure comparison"""
        return hashlib.sha256(str(user_id).encode()).hexdigest()

    def _get_user_by_username(self, username: str) -> dict | None:
        """Get user by username"""
        with closing(_get_connection()) as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()
            return dict(row) if row else None


# Initialize storage with persistent SQLite database
vault_storage = VaultStorage(DB_PATH)

# Create FastAPI app
app = FastAPI(
    title="Password Manager Cloud API",
    description="Secure vault storage for password manager synchronization",
    version="1.0.0",
)

# CORS middleware - allow connections from the desktop app
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://password-manager-cloud.*.up.railway.app",
        "https://*.up.railway.app",
        "http://localhost:8000",  # For development
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

security = HTTPBearer(auto_error=False)


class RegisterVaultRequest(BaseModel):
    vault_id: str = Field(..., min_length=1)
    blob: str = Field(...)


class GetVaultResponse(BaseModel):
    vault_id: str
    blob: str
    version: int
    updated_at: str


class VaultBlobRequest(BaseModel):
    blob: str = Field(...)
    expected_version: Optional[int] = Field(default=None, ge=0)


@app.get("/")
async def root():
    """Health check endpoint"""
    return {"status": "ok", "service": "Password Manager Cloud API"}


@app.post("/v1/vaults", response_model=GetVaultResponse, status_code=status.HTTP_201_CREATED)
async def register_vault(
    request: RegisterVaultRequest,
    user: dict = Depends(get_current_user),
):
    """Register a new vault on the server"""
    try:
        validate_vault_id(request.vault_id)
        check_blob_size(request.blob)
        vault = vault_storage.create_vault(
            vault_id=request.vault_id,
            user_id=user["id"],
            blob=request.blob,
        )
        return GetVaultResponse(
            vault_id=vault["vault_id"],
            blob=vault["blob"],
            version=vault["version"],
            updated_at=vault["updated_at"],
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create vault: {str(e)}")


@app.get("/v1/vaults/{vault_id}", response_model=GetVaultResponse)
async def get_vault(
    vault_id: str,
    user: dict = Depends(get_current_user),
):
    """Download the current vault state"""
    try:
        vault = vault_storage.get_vault(
            vault_id=validate_vault_id(vault_id),
            user_id=user["id"],
        )
        return GetVaultResponse(
            vault_id=vault["vault_id"],
            blob=vault["blob"],
            version=vault["version"],
            updated_at=vault["updated_at"],
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve vault: {str(e)}")


@app.put("/v1/vaults/{vault_id}", response_model=GetVaultResponse)
async def upload_vault(
    payload: VaultBlobRequest,
    vault_id: str,
    user: dict = Depends(get_current_user),
):
    """Upload a new version of the vault blob"""
    try:
        vault = vault_storage.update_vault(
            vault_id=validate_vault_id(vault_id),
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
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update vault: {str(e)}")


@app.delete("/v1/vaults/{vault_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vault(
    vault_id: str,
    user: dict = Depends(get_current_user),
):
    """Delete the vault from the server"""
    try:
        vault_storage.delete_vault(vault_id, user["id"])
        return {"status": "deleted", "vault_id": vault_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete vault: {str(e)}")


class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    email: Optional[EmailStr] = None


class UserLoginRequest(BaseModel):
    username: str = Field(...)
    password: str = Field(...)


class UserResponse(BaseModel):
    user_id: int
    username: str
    email: Optional[str] = None
    access_token: str
    token_type: str = "bearer"


@app.post("/v1/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user(request: UserRegisterRequest):
    """Register a new user."""
    with closing(_get_connection()) as connection:
        # Check if username exists
        existing = connection.execute(
            "SELECT * FROM users WHERE username = ?",
            (request.username,)
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Username already exists")
        
        # Create user
        now = datetime.now(timezone.utc).isoformat()
        password_hash = hashlib.sha256(request.password.encode()).hexdigest()
        connection.execute(
            "INSERT INTO users (username, password_hash, email, created_at) VALUES (?, ?, ?, ?)",
            (request.username, password_hash, request.email, now)
        )
        connection.commit()
        
        # Get user ID and create access token
        user = connection.execute(
            "SELECT id, username, email FROM users WHERE username = ?",
            (request.username,)
        ).fetchone()
        
        token = create_access_token(data={"sub": user["username"]})
        return UserResponse(
            user_id=user["id"],
            username=user["username"],
            email=user["email"],
            access_token=token
        )


@app.post("/v1/auth/login", response_model=UserResponse)
async def login_user(request: UserLoginRequest):
    """Login and get access token."""
    user_data = verify_user(request.username, request.password)
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token(data={"sub": user_data["username"]})
    return UserResponse(
        user_id=user_data["id"],
        username=user_data["username"],
        email=user_data["email"],
        access_token=token
    )


@app.get("/v1/auth/me")
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer(auto_error=False))
):
    """Get current authenticated user info."""
    try:
        payload = decode_token(credentials.credentials)
        user = vault_storage._get_user_by_username(payload["sub"])
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return {
            "user_id": user["id"],
            "username": user["username"],
            "email": user["email"]
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get user: {str(e)}")


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """Validate Bearer token and return user data"""
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing authentication")
    try:
        payload = decode_token(credentials.credentials)
        user = vault_storage._get_user_by_username(payload["sub"])
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user")
        return user
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Authentication failed: {str(e)}")


def validate_vault_id(vault_id: str) -> str:
    """Validate vault ID format and return it"""
    if not VAULT_ID_PATTERN.fullmatch(vault_id):
        raise HTTPException(status_code=400, detail="Invalid vault id format")
    return vault_id


def check_blob_size(blob: str) -> None:
    """Check if blob size exceeds maximum"""
    if len(blob.encode("utf-8")) > MAX_BLOB_BYTES:
        raise HTTPException(status_code=413, detail="Encrypted vault is too large")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
