# Configuració del Servei Railway

Aquest fitxer explica com configurar el servei Railway perquè pugui comunicar-se amb el client de l'aplicació de gestió de contrasenyes.

## Estructura de Dades

L'API utilitza una estructura senzilla basada en identificadors i tokens:

### Registre de Caixa Forta (Primera Experiència)

Quan es crea una nova caixa forta per primera vegada, el client genera:

- **vault_id**: UUID genèric per identificar la caixa forta
- **token**: Token d'autenticació (salt aleatori)
- **blob**: Les dades de la caixa forta en format blocat

### Obtenir/Oferir una Caixa Forta Existente

Per descarregar/actualitzar una caixa forta ja existent:

- **vault_id**: El mateix UUID que es va utilitzar per crear la caixa forta
- **token**: El token d'autenticació (es passa com a `expected_version` per a la verificació de conflicte)

## Exemples d'Ús

### Registrar una Nova Caixa Forta

```bash
# Primer, genera credencials del client
python -c "from src.railway_client import create_vault_credentials; print(create_vault_credentials())"

# Resultat:
# vault_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
# token: "X9y8Z7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2H1g0F"

# Pujar la caixa forta blocada (vuitat primer)
curl -X POST https://el-teu-servici.up.railway.app/v1/vaults \
  -H "Content-Type: application/json" \
  -d '{
    "vault_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "token": "X9y8Z7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2H1g0F",
    "blob": "{}"
  }'
```

### Descarregar Caixa Forta

```bash
curl -X GET https://el-teu-servici.up.railway.app/v1/vaults/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -H "Authorization: Bearer X9y8Z7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2H1g0F"
```

### Pujar Actualitzacions

```bash
# Blocar actualitzacions amb control de versió
curl -X PUT https://el-teu-servici.up.railway.app/v1/vaults/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer X9y8Z7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2H1g0F" \
  -d '{
    "vault_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "token": "version-1",  # Compara amb la versió actual
    "blob": "{dades blocades}"
  }'
```

### Eliminar Caixa Forta

```bash
curl -X DELETE https://el-teu-servici.up.railway.app/v1/vaults/a1b2c3d4-e5f6-7890-abcd-ef1234567890 \
  -H "Authorization: Bearer X9y8Z7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2H1g0F"
```

## Erros Comuns

### 409 Vault Already Exists

Es va provar de crear una caixa forta amb el mateix `vault_id`. Utilitza un identificador únic.

### 404 Vault Not Found

El `vault_id` no existeix o es va eliminar. Crea una nova caixa forta.

### 409 Version Conflict

Hi ha hagut un conflicte de versió. Aquest passa quan dues instàncies intenten actualitzar alhora. El client reprendrà amb la nova versió automàticament.

## Flux de Funcionament

```
Usuari 1 (macOS)     Railway API     Usuari 2 (Windows)
    │                   │                   │
    ├─── Crea caixa ───→│                   │
    │                   │                   │
    │                   ├─── Crea i guarda │
    │                   │                   │
    ├─── Dóna les dades─→│                   │
    │                   │                   │
    ├─── Descarrega ───→│                   │
    │                   │                   │
    │                   ├─── Obre i envia │
    │                   │                   │
    │                   └───────────────────→
    │                   │
```

## Codi del Client

El codi del client ja està preparat per connectar:

```python
from src.railway_client import RailwayVaultClient

# Configura les credencials del servei Railway
RAILWAY_URL = "https://el-teu-servici.up.railway.app"
VAULT_ID = "el-teu-vault-id"
TOKEN = "el-teu-token"

client = RailwayVaultClient(RAILWAY_URL, VAULT_ID, TOKEN)

# Descarregar la caixa forta
vault = client.download()
entries = deserialize_vault(vault.blob, "password-mestra")

# Pujar actualitzacions
client.upload(encrypted_blob)
```
