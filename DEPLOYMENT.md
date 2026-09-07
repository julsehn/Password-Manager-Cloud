# Desplegament a Railway

## Pasos per Desplegar

### Important: Ferres de Desplegament

Railway's free tier blocks automatic deployments between **8 AM - 8 PM Europe/Amsterdam time (CEST)**. The service will deploy automatically at any other time.

### 1. Crea un Projecte a Railway

1. Ves a https://railway.app
2. Sign in o sign up (GitHub recomanat)
3. Crea un nou projecte anomenat "password-manager-cloud"

### 2. Connecta el Repositori

1. A Railway, ves a "Sources"
2. Connecta GitHub
3. Connecta el repositori: `juls/The-vault-project`
4. Selecciona la branca `main`
5. Railway auto-desplegarà al finalitzar el ferre (després de les 8 PM)

### 3. Verifica el Desplegament

Un cop desplegat, verifica que l'estat sigui "Running" o "Success" a la dashboard.

### 4. Obtingues l'URL del Servidor

Un cop desplegat, veuràs l'URL de producció a la dashboard de Railway:
```
https://password-manager-cloud-<random>.up.railway.app
```

### 5. Verifica el Servei

Obre http://your-project-name.up.railway.app i hauries de veure:

```json
{
  "status": "ok",
  "service": "Password Manager Cloud API"
}
```

### 6. Configura Variables d'Entorn (Opcional)

Si vols variar el port o altres configuracions, afegeix variables d'entorn:

1. A Railway Dashboard, va al teu servei
2. Anota "Variables"
3. Afegeix si cal:
   - `MAX_BLOB_BYTES`: 10485760 (default 10MB, en bytes)
   - `SECRET_KEY`: (opcional, per a tokens JWT futurs)

## Verifica el Desplegament

Obre http://your-project-name.up.railway.app i hauries de veure:

```json
{
  "status": "ok",
  "service": "Password Manager Cloud API"
}
```

## Recursos Estimat

Aquest API utilitza molt pocs recursos:

- **CPU**: < 10% de l'assignat
- **RAM**: 256MB per defecte (suficient)
- **Bandwidth**: Baix (dades blocades)

## Escalar

Si necessites més recursos o vols un port específic:

1. A Railway Dashboard, ves a "Settings" -> "Variables"
2. Modifica els recursos si cal

## Instal·lació Manual (Opcional)

Si no vols usar l'auto-desplegament:

```bash
# Construeix imatge Docker
cd password-manager-cloud
docker build -t password-manager-cloud .

# Pujar a Docker Hub (opcional)
docker push julsehn/password-manager-cloud

# Desplegar amb Railway CLI (si l'as instal·lat)
railway up --project password-manager-cloud
```

## API Endpoints

- `GET /` - Health check
- `POST /v1/vaults` - Register new vault
- `GET /v1/vaults/{vault_id}` - Download vault (requires Bearer token)
- `PUT /v1/vaults/{vault_id}` - Upload vault version (requires Bearer token)
- `DELETE /v1/vaults/{vault_id}` - Delete vault (requires Bearer token)

## Manteniment

### Actualitzar el Codi

1. Cometeu les canvis i pugeu a GitHub
2. Railway auto-desplegarà el canvi
3. Verifica que el servei segueixi sent operatiu

### Monitoreig

Pots veure logs i mètriques a la dashboard de Railway:

- **Logs**: Dashboard -> Logs
- **Mètriques**: Dashboard -> Metrics

## En cas d'Errors

Si el servei falla:

1. Revisa els **Logs** a Railway Dashboard
2. Comprova que les dependències (`requirements.txt`) siguin correctes
3. Assegura't que no hi ha errors de sintaxi al codi Python
4. Ves a "Deployment" i reinicia si cal
