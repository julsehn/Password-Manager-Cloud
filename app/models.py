"""Pydantic models for API validation"""
from pydantic import BaseModel, Field


class VaultEntry(BaseModel):
    """Represents a single password entry"""
    id: str = Field(..., description="Unique identifier for the entry")
    site: str = Field(..., description="Website or service name")
    username: str = Field(default="", description="Username or email")
    password: str = Field(..., description="Password")
    notes: str = Field(default="", description="Optional notes")
    created_at: str = Field(default="", description="ISO timestamp of creation")
    updated_at: str = Field(default="", description="ISO timestamp of last update")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "site": "example.com",
                "username": "user@example.com",
                "password": "securepassword123",
                "notes": "Business account",
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-20T14:45:00Z"
            }
        }


class VaultBlobResponse(BaseModel):
    """Response from vault operations"""
    vault_id: str = Field(..., description="Unique vault identifier")
    blob: str = Field(..., description="Encrypted vault blob")
    version: int = Field(..., description="Version number for optimistic locking")
    updated_at: str = Field(..., description="ISO timestamp of last update")


class RegisterVaultRequest(BaseModel):
    """Request body for vault registration"""
    vault_id: str = Field(..., min_length=1, description="Unique vault identifier")
    token: str = Field(..., min_length=1, description="Authentication token")
    blob: str = Field(..., description="Encrypted vault blob")
