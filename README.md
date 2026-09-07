# Password Manager Cloud API

Secure vault storage service for password manager synchronization via Railway with persistent SQLite storage.

## Overview

This service provides a REST API for storing and retrieving encrypted vaults. All encryption happens on the client side (desktop app), ensuring passwords never leave the device in plaintext. Data is persisted using SQLite with write-ahead logging (WAL) for durability.

## Features

- **End-to-End Encryption**: AES-256-GCM encryption with PBKDF2-SHA256 key derivation (600k iterations per OWASP 2023)
- **Persistent Storage**: SQLite database with WAL mode for crash-safe operations
- **Optimistic Locking**: Version-based conflict detection for simultaneous updates
- **Token-based Auth**: Secure SHA256 token digests for vault access control
- **REST API**: Simple JSON endpoints for vault operations
- **Railway Ready**: Deployed as a Railway service with persistent volumes

## API Endpoints

### Register Vault
```http
POST /v1/vaults
Content-Type: application/json

{
  "vault_id": "unique-vault-id",
  "token": "auth-token",
  "blob": "encrypted-vault-blob"
}
```
Creates a new vault with the provided encrypted blob.

### Download Vault
```http
GET /v1/vaults/{vault_id}
Authorization: Bearer {token}
```
Retrieves the current vault state. Requires valid Bearer token.

### Upload Vault
```http
PUT /v1/vaults/{vault_id}
Content-Type: application/json
Authorization: Bearer {token}

{
  "vault_id": "unique-vault-id",
  "blob": "encrypted-vault-blob",
  "expected_version": 1
}
```
Uploads a new version of the vault with optimistic version checking.

### Delete Vault
```http
DELETE /v1/vaults/{vault_id}
Authorization: Bearer {token}
```
Deletes the vault from the server.

## Deployment

### Railway
1. Create a new Railway project
2. Connect this repository
3. Railway will automatically create persistent volumes for `/data`
4. Environment variables (optional for production):
   - `SECRET_KEY`: For JWT signing (reserved for future use)
   - `CORS_ORIGINS`: Comma-separated list of allowed origins
   - `MAX_BLOB_BYTES`: Maximum vault size in bytes (default: 10MB)
5. Deploy

### Docker
```bash
docker build -t password-manager-cloud .
docker run -p 8000:8000 -v $(pwd)/data:/data password-manager-cloud
```

## Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run locally with persistent storage
mkdir -p data
uvicorn app.main:app --reload --port 8000 --workers 2
```

## Database Schema

```sql
CREATE TABLE vaults (
    vault_id TEXT PRIMARY KEY,
    token_digest TEXT NOT NULL,
    blob TEXT NOT NULL,
    version INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
```

## Security Considerations

1. **Client-side Encryption**: All password data is encrypted before leaving the client
2. **No Password Storage**: The server only stores encrypted blobs
3. **Version Locking**: Prevents simultaneous updates from corrupting data
4. **Token Digests**: SHA256 digests prevent token leakage
5. **WAL Mode**: Write-ahead logging ensures durability during crashes
6. **Volume Persistence**: SQLite database persists across deployments
