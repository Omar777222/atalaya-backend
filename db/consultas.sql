-- Consultas útiles para la documentación y el análisis de incidentes.
-- Abrir la consola:  psql "postgres://atalaya:CONTRASEÑA@127.0.0.1:5432/atalaya"   (o: sudo -u postgres psql -d atalaya)

-- 1. Tablas del sistema
\dt

-- 2. Alertas por sensor y por prueba de la práctica
SELECT sensor, objective, count(*) AS alertas, max(ts) AS ultima
FROM ids_alerts GROUP BY sensor, objective ORDER BY sensor, objective;

-- 3. Las 3 alertas que se analizan en la memoria (una por objetivo, la más reciente)
SELECT DISTINCT ON (objective) objective, sensor, sid, message, src_ip, dst_ip, ts
FROM ids_alerts WHERE objective IN ('icmp', 'sniffer', 'nmap') ORDER BY objective, ts DESC;

-- 4. Orígenes con más alertas (posibles atacantes)
SELECT src_ip, count(*) AS alertas, array_agg(DISTINCT sid) AS reglas
FROM ids_alerts GROUP BY src_ip ORDER BY alertas DESC LIMIT 10;

-- 5. Quién entró al sitio (últimos 20 accesos)
SELECT ts, type, username, ip, detail FROM audit_events
WHERE type IN ('LOGIN_SUCCESS', 'LOGIN_FAILURE', 'LOGOUT', 'ACCESS_DENIED') ORDER BY id DESC LIMIT 20;

-- 6. Intentos fallidos por IP (fuerza bruta)
SELECT ip, count(*) AS fallos, min(ts) AS primero, max(ts) AS ultimo
FROM audit_events WHERE type = 'LOGIN_FAILURE' GROUP BY ip ORDER BY fallos DESC;

-- 7. Usuarios (nunca se guarda la contraseña, solo su hash bcrypt)
SELECT u.username, u.role, c.name AS empresa, u.active, u.updated_at
FROM users u LEFT JOIN clients c ON c.id = u.client_id ORDER BY u.id;

-- 8. Reinicios de contadores hechos antes de cada demo
SELECT reset_at, reset_by, cursor FROM ids_resets ORDER BY id DESC;
