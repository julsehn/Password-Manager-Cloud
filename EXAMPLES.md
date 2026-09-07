# Exemples d'Ús

Aquest fitxer conté exemples de còdic per utilitzar l'API del Password Manager Cloud.

## Python

```python
import sys
from pathlib import Path
from src.railway_client import RailwayVaultClient, create_vault_credentials
from src.encryption import serialize_vault, deserialize_vault
from src.models import PasswordEntry
from src.config import get_railway_url, get_railway_vault_id, get_railway_token

def main():
    """Exemple bàsic per crear, sincronitzar i utilitzar una caixa forta"""
    
    # Configura el client Railway
    url = get_railway_url()
    vault_id = get_railway_vault_id()
    token = get_railway_token()
    
    client = RailwayVaultClient(url, vault_id, token)
    
    # Crea una contrasenya mestra
    master_password = "la-teu-contrasenya-mestra-1234567890"  # Mínim 16 caràcters
    
    # Crea una nova entrada
    entry = PasswordEntry(
        site="github.com",
        username="el teu usuari",
        password="la-teu-contrasenya-github",
        notes="Compte principal"
    )
    
    entries = [entry]
    
    # Serialitza les dades amb la contrasenya mestra
    blob = serialize_vault(entries, master_password)
    
    # Registra la caixa forta (primera vegada)
    if not get_railway_vault_id():
        remote = client.register(blob)
        print(f"Registra: vault_id={remote.vault_id}, version={remote.version}")
        return
    
    # Descarrega la caixa forta
    remote = client.download()
    entries = deserialize_vault(remote.blob, master_password)
    print(f"Descarregat {len(entries)} entrades")
    
    # Actualitza una entrada
    for e in entries:
        if e.site == "github.com":
            e.notes = "Compte principal - Actualitzat"
            break
    
    # Pujar les actualitzacions amb control de versió
    blob = serialize_vault(entries, master_password)
    client.upload(blob, expected_version=remote.version)
    print("Actualitzacions pujades amb èxit")

if __name__ == "__main__":
    main()
```

## Còdiga shell (curl)

### Registrar una nova caixa forta

```bash
# Generar credencials (hauria de fer el codi client)
vault_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890"
token="X9y8Z7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2H1g0F"
blob='{"salt":"...","nonce":"...","ciphertext":"...","version":"1"}'

curl -X POST https://api.password-manager.cloud/v1/vaults \
  -H "Content-Type: application/json" \
  -d "{
    \"vault_id\": \"${vault_id}\",
    \"token\": \"${token}\",
    \"blob\": \"${blob}\"
  }"
```

### Descarregar una caixa forta

```bash
vault_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890"
token="X9y8Z7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2H1g0F"

curl -X GET https://api.password-manager.cloud/v1/vaults/${vault_id} \
  -H "Authorization: Bearer ${token}" | jq '.'
```

### Actualitzar una caixa forta

```bash
vault_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890"
token="X9y8Z7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2H1g0F"
blob='{"salt":"...","nonce":"...","ciphertext":"...","version":"1"}'

curl -X PUT https://api.password-manager.cloud/v1/vaults/${vault_id} \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${token}" \
  -d "{
    \"vault_id\": \"${vault_id}\",
    \"token\": \"${token}\",
    \"blob\": \"${blob}\"
  }"
```

### Eliminar una caixa forta

```bash
vault_id="a1b2c3d4-e5f6-7890-abcd-ef1234567890"
token="X9y8Z7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2H1g0F"

curl -X DELETE https://api.password-manager.cloud/v1/vaults/${vault_id} \
  -H "Authorization: Bearer ${token}"
```

## Node.js

```javascript
const axios = require('axios');

const RAILWAY_URL = 'https://api.password-manager.cloud';
const VAULT_ID = 'el-teu-vault-id';
const TOKEN = 'el-teu-token';
const MASTER_PASSWORD = 'la-teu-mestra-16caracters';

async function main() {
  const client = axios.create({
    baseURL: `${RAILWAY_URL}/v1/vaults`,
    headers: {
      'Authorization': `Bearer ${TOKEN}`,
      'Content-Type': 'application/json',
    },
  });

  // Descarregar la caixa forta
  const response = await client.get(`/${VAULT_ID}`);
  const vault = response.data;
  
  // Processa les dades blocades aquí
  console.log(`Descarregada versió ${vault.version}`);
  
  // Pujar actualitzacions
  const blob = '{"salt":"...","nonce":"...","ciphertext":"...","version":"1"}';
  await client.put(`/${VAULT_ID}`, {
    vault_id: VAULT_ID,
    token: TOKEN,
    blob: blob,
  });
  
  console.log("Actualitzacions pujades");
}

main().catch(console.error);
```

## Go

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
)

type VaultRequest struct {
    VaultID string `json:"vault_id"`
    Token   string `json:"token"`
    Blob    string `json:"blob"`
}

type VaultResponse struct {
    VaultID string `json:"vault_id"`
    Blob    string `json:"blob"`
    Version int    `json:"version"`
}

func main() {
    url := "https://api.password-manager.cloud/v1/vaults"
    vaultID := "el-teu-vault-id"
    token := "el-teu-token"
    
    // Registre una nova caixa forta
    reqBody := VaultRequest{
        VaultID: vaultID,
        Token:   token,
        Blob:    "{}",
    }
    
    jsonData, _ := json.Marshal(reqBody)
    resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    
    // Processa la resposta...
}
```

## TypeScript (Frontend)

```typescript
interface VaultResponse {
  vault_id: string;
  blob: string;
  version: number;
  updated_at: string;
}

const RAILWAY_URL = 'https://api.password-manager.cloud';

async function getVault(vaultId: string, token: string): Promise<VaultResponse> {
  const response = await fetch(`${RAILWAY_URL}/v1/vaults/${vaultId}`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Accept': 'application/json',
    },
  });
  
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  
  return response.json();
}

async function updateVault(vaultId: string, token: string, blob: string): Promise<VaultResponse> {
  const response = await fetch(`${RAILWAY_URL}/v1/vaults/${vaultId}`, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      vault_id: vaultId,
      token: token,
      blob: blob,
    }),
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Unknown error');
  }
  
  return response.json();
}

// Ús
(async () => {
  try {
    const vault = await getVault('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'token123');
    console.log(`Versió: ${vault.version}`);
    
    const updated = await updateVault('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'token123', 'blob');
    console.log('Actualitzat!');
  } catch (error) {
    console.error('Error:', error);
  }
})();
```

## Rust

```rust
use reqwest;
use serde_json::json;

#[derive(serde::Deserialize)]
struct VaultResponse {
    vault_id: String,
    blob: String,
    version: i32,
    updated_at: String,
}

async fn get_vault(vault_id: &str, token: &str) -> Result<VaultResponse, reqwest::Error> {
    let client = reqwest::Client::new();
    let response = client
        .get(format!("https://api.password-manager.cloud/v1/vaults/{}", vault_id))
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?
        .json()
        .await?;
    
    Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vault_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    let token = "token123";
    
    let vault = get_vault(vault_id, token).await?;
    println!("Versió: {}", vault.version);
    
    Ok(())
}
```

## Errors Comuns

### 409 Vault Already Exists
```json
{
  "detail": "Vault already exists"
}
```
**Solució**: El `vault_id` ja existeix. Utilitza un identificador únic.

### 404 Vault Not Found
```json
{
  "detail": "Vault not found"
}
```
**Solució**: El `vault_id` no existeix. Crea una nova caixa forta primer.

### 409 Version Conflict
```json
{
  "detail": "Version conflict: expected 1, got 2"
}
```
**Solució**: Hi ha hagut un conflicte de versió. L'altra instància actualitzà alhora. Actualitza amb la nova versió del servidor.

### 401 Unauthorized
```json
{
  "detail": "Invalid token"
}
```
**Solució**: El token és invàlid. Verifica que estàs enviant el token correcte.

## Referència de la API

| Mètode | Endpoint | Descripció |
|--------|----------|------------|
| `POST` | `/v1/vaults` | Registrar nova caixa forta |
| `GET` | `/v1/vaults/{vault_id}` | Descarregar caixa forta |
| `PUT` | `/v1/vaults/{vault_id}` | Actualitzar caixa forta |
| `DELETE` | `/v1/vaults/{vault_id}` | Eliminar caixa forta |

## Preguntes Freqüents

**Q: Com genero una caixa forta única?**
A: Utilitza `uuid.uuid4().hex` per crear un `vault_id` únic.

**Q: Què és el token?**
A: El token s'utilitza per a autenticació i control de versió. Genera un string aleatori amb `secrets.token_urlsafe(32)`.

**Q: Com manejo els conflictes de versió?**
A: Inclou `expected_version` en el `PUT` request. Si el servidor té una versió diferent, obtindràs un 409 i hauràs de tornar a descarregar amb la nova versió.
