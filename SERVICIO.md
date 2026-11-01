# Atalaya SOC · Concepto de servicio

Idea de producto para reutilizar el proyecto: **monitoreo de seguridad gestionado (SOC/MSSP) para pequeños negocios en la nube**.
Un equipo de seguridad (admin y analistas) vigila el sitio web de cada cliente con dos sensores y el cliente ve el estado
de su protección en un portal sencillo.

## Roles

| Rol | Quién es | Qué ve |
|---|---|---|
| `admin` | Responsable del SOC | Todo: monitoreo, alertas, sensores, demo, auditoría, reinicio de contadores y la vista del cliente |
| `analyst` | Analista de seguridad | Monitoreo, alertas, sensores y demo (sin auditoría) |
| `client` | Dueño del sitio protegido | Solo **Mi sitio**: estado, ataques por día y "qué pasó / qué hicimos", sin IPs internas ni reglas |

El cliente se crea con una tercera contraseña: `npm run setup -- "Admin…" "Analista…" "Cliente…"`.
Si intenta abrir una ruta técnica, la API responde 403, queda en auditoría y se avisa por Telegram.

## Qué llega al grupo de Telegram

- **Alertas de los IDS** (Suricata y Snort) con sensor, SID, origen → destino y la prueba a la que corresponden.
- **Accesos al sitio** (auditoría de la API): inicios de sesión con rol e IP, intentos fallidos (agrupados si son
  fuerza bruta), cierres de sesión, accesos denegados por rol, clave del agente rechazada y reinicios del panel.
  Se eligen con `TELEGRAM_AUDIT_TYPES` en `agente.env`.
- Comandos: `/estado`, `/ultimas`, `/accesos`, `/ayuda`.

## Línea base de seguridad reutilizable (checklist para un proyecto nuevo)

1. Red: frontend y backend en VPC separadas con peering; backend sin ruta a internet.
2. Security Groups con origen /32 y UFW con *deny* por defecto en cada instancia.
3. Entrada única por ALB + AWS WAF (reglas administradas SQLi/XSS/IP reputation + límite por IP).
4. HTTPS con certificado válido; HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy.
5. API: JWT corto (15 min) con revocación, roles con mínimo privilegio, validación de entradas, errores genéricos.
6. Fail2Ban sobre el login, con la IP real que envía Nginx.
7. Detección: Suricata en la entrada (NIDS) y Snort en el servidor (HIDS) con reglas locales probadas.
8. Respuesta: alertas y accesos en Telegram; auditoría consultable; CloudWatch y CloudTrail.
9. Secretos solo en `.env` / `agente.env` con permisos 600, nunca en el repositorio.

## Siguientes pasos si se vuelve un proyecto real

- ✅ **Base de datos PostgreSQL** (hecho): usuarios, clientes, auditoría, sesiones revocadas e histórico de alertas.
  Siguiente nivel: moverla a Amazon RDS con respaldos automáticos y cifrado en reposo.
- **Varios clientes** (multi-tenant): cada alerta llevaría el sitio al que pertenece y cada cliente vería solo el suyo.
- **TLS en el tramo interno** (Nginx → API) para cerrar el hallazgo "datos sensibles sin cifrar".
- SIEM (Grafana/Loki o Wazuh) y modo IPS para bloquear automáticamente.
