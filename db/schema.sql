-- Atalaya · Esquema de PostgreSQL (idempotente: se puede ejecutar varias veces)
-- La API lo aplica sola al arrancar; también se puede correr a mano:
--   psql "$DATABASE_URL" -f db/schema.sql

-- Clientes del servicio (empresas cuyo sitio vigila Atalaya SOC)
CREATE TABLE IF NOT EXISTS clients (
  id          serial PRIMARY KEY,
  name        text NOT NULL,
  site        text NOT NULL UNIQUE,
  plan        text NOT NULL DEFAULT 'Profesional' CHECK (plan IN ('Básico', 'Profesional', 'Empresa')),
  contact     text,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Usuarios: equipo del SOC (admin, analyst) y clientes (client). Solo se guarda el hash bcrypt.
CREATE TABLE IF NOT EXISTS users (
  id            serial PRIMARY KEY,
  username      text NOT NULL UNIQUE CHECK (username ~ '^[a-zA-Z0-9._-]{3,30}$'),
  display_name  text NOT NULL,
  role          text NOT NULL CHECK (role IN ('admin', 'analyst', 'client')),
  password_hash text NOT NULL CHECK (password_hash LIKE '$2%'),
  client_id     integer REFERENCES clients(id) ON DELETE SET NULL,
  active        boolean NOT NULL DEFAULT true,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  CHECK (role <> 'client' OR client_id IS NOT NULL)
);

-- Auditoría de la aplicación: inicios de sesión, fallos, accesos denegados, etc.
CREATE TABLE IF NOT EXISTS audit_events (
  id          bigserial PRIMARY KEY,
  event_id    uuid NOT NULL UNIQUE,
  ts          timestamptz NOT NULL,
  type        text NOT NULL,
  severity    text NOT NULL,
  username    text,
  ip          text,
  path        text,
  detail      text,
  request_id  text
);
CREATE INDEX IF NOT EXISTS audit_events_type_id ON audit_events (type, id DESC);
CREATE INDEX IF NOT EXISTS audit_events_ts ON audit_events (ts DESC);

-- Sesiones cerradas antes de expirar (el cierre de sesión sobrevive a un reinicio de la API)
CREATE TABLE IF NOT EXISTS revoked_tokens (
  jti         text PRIMARY KEY,
  expires_at  timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS revoked_tokens_expires ON revoked_tokens (expires_at);

-- Histórico de alertas de Snort y Suricata
CREATE TABLE IF NOT EXISTS ids_alerts (
  id              bigserial PRIMARY KEY,
  sensor          text NOT NULL CHECK (sensor IN ('snort', 'suricata')),
  ts              timestamptz NOT NULL,
  gid             integer NOT NULL DEFAULT 1,
  sid             integer NOT NULL,
  rev             integer NOT NULL DEFAULT 1,
  message         text NOT NULL,
  classification  text,
  priority        smallint,
  protocol        text,
  src_ip          text,
  src_port        integer,
  dst_ip          text,
  dst_port        integer,
  objective       text,
  local_rule      boolean NOT NULL DEFAULT false,
  raw             text,
  extra           jsonb,
  fingerprint     text NOT NULL UNIQUE,      -- evita duplicados si la API vuelve a leer el log
  received_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ids_alerts_ts ON ids_alerts (ts DESC);
CREATE INDEX IF NOT EXISTS ids_alerts_sensor_id ON ids_alerts (sensor, id DESC);
CREATE INDEX IF NOT EXISTS ids_alerts_objective_id ON ids_alerts (objective, id DESC);

-- "Reiniciar contadores" no borra el histórico: solo marca desde qué alerta empieza la demo
CREATE TABLE IF NOT EXISTS ids_resets (
  id          serial PRIMARY KEY,
  cursor      bigint NOT NULL,
  reset_by    text,
  reset_at    timestamptz NOT NULL DEFAULT now()
);
