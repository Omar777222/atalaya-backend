# Atalaya · Backend (API + Snort HIDS)

API REST en Node.js + Express con **arquitectura hexagonal**, JWT, roles, auditoría y el **centro de monitoreo IDS**:
lee las alertas de **Snort** en este mismo servidor (ec2-backend) y recibe las de **Suricata** que envía el agente de ec2-frontend.
Práctica 2.4 · IDS como sistema de defensa (sobre el proyecto Zero Trust en AWS).

## Estructura

```
src/
  domain/          Entidades (User, SecurityEvent, IdsAlert), catálogo de detección y puertos
    catalog/       detectionCatalog.js: objetivos de la práctica y TODAS las reglas locales (fuente única)
  application/     Casos de uso: login/sesión/auditoría + GetIdsOverview, ListIdsAlerts, GetIdsSetup,
                   IngestSuricataAlerts, RecordSensorHeartbeat, GetAlertFeed, ResetIdsAlerts
  infrastructure/  Express (http), JWT y bcrypt (security), memoria (persistence),
    ids/           FileTailer + SnortLogWatcher (alert_fast.txt), parsers fast/eve.json, monitor de sensores
ids/snort/         local.rules, fragmentos de snort.conf y snort.debian.conf, permisos y script de evidencias
scripts/           setup-env, export-rules (genera los .rules), demo-alerts (solo desarrollo local)
test/              node --test
```

## Base de datos (PostgreSQL)

Con `DATABASE_URL` en el `.env` la API usa PostgreSQL; sin ella, memoria (desarrollo). Los casos de uso no cambian:
solo se conecta otro adaptador a cada puerto (`src/infrastructure/persistence/postgres/`).

| Tabla | Qué guarda |
|---|---|
| `clients` | Empresas cliente del servicio (nombre, sitio, plan, contacto) |
| `users` | Equipo del SOC y clientes; solo el hash bcrypt, rol validado con CHECK |
| `audit_events` | Inicios de sesión, fallos, accesos denegados… (lo que también llega a Telegram) |
| `revoked_tokens` | Sesiones cerradas: el logout sigue valiendo aunque la API se reinicie |
| `ids_alerts` | Histórico de alertas de Snort y Suricata, sin duplicados (`fingerprint` único) |
| `ids_resets` | "Reiniciar contadores" marca el inicio de la demo sin borrar el histórico |

Esquema: `db/schema.sql` · instalación segura en ec2-backend: `db/instalar-postgresql.sh` ·
respaldo diario: `db/respaldo-postgresql.sh` · consultas para la memoria: `db/consultas.sql`.
Seguridad: escucha solo en `localhost`, `scram-sha-256`, usuario sin superusuario, consultas parametrizadas, secretos solo en `.env`.

## Endpoints

| Método | Ruta | Acceso |
|---|---|---|
| GET | /api/health | Público |
| POST | /api/auth/login · GET /api/auth/me · POST /api/auth/logout | Público / Token |
| GET | /api/ids/overview | admin, analyst |
| GET | /api/ids/alerts?sensor=&objective=&after=&limit= | admin, analyst |
| GET | /api/ids/setup | admin, analyst |
| POST | /api/ids/reset | admin (queda en auditoría) |
| GET | /api/client/summary | client, admin (portal "Mi sitio", sin IPs internas) |
| GET | /api/audit | admin |
| POST | /api/internal/ids/suricata · /heartbeat · GET /ids/feed · /ids/status · /audit/feed | Clave `X-Atalaya-Key` (solo el agente; Nginx las bloquea desde internet) |

## Reglas

Las reglas se editan en `src/domain/catalog/detectionCatalog.js` y se generan con `npm run rules:export`
(`ids/snort/local.rules` aquí y `ids/suricata/*.rules` en el repositorio del frontend).

## Ejecutar en local (sin AWS)

```bash
npm install
npm run setup -- "ContraseñaAdmin" "ContraseñaAnalista" "ContraseñaCliente" --snort-file ./samples/alert_fast.txt
# opcional, con PostgreSQL local: agrega --database-url postgres://atalaya:CLAVE@127.0.0.1:5432/atalaya
npm run dev
npm run demo -- all     # SOLO desarrollo: simula alertas para ver la interfaz. No es evidencia.
npm test
```

Despliegue en AWS: ver `GUIA_DESPLIEGUE_IDS.md`. Concepto de servicio y roles: `SERVICIO.md`.
