# Atalaya IDS · Guía de despliegue en AWS (paso a paso)

Práctica 2.4 · IDS como sistema de defensa. **Suricata (NIDS) en ec2-frontend** y **Snort (HIDS) en ec2-backend**,
alertas en el sitio y en Telegram. Cada `📸 Fxx` marca una captura para la memoria: tómala justo en ese momento.

> Convenciones: `FRONT_PUB` = IP pública actual de ec2-frontend (cambia en cada sesión del Learner Lab),
> `10.0.0.10` = ec2-frontend, `10.0.128.10` = ec2-backend, `KALI_IP` = IP pública de tu casa/Kali (`curl ifconfig.me`).

---

## 0. Antes de empezar (5 min)

1. Inicia el Learner Lab y anota la IP pública nueva de ec2-frontend. 📸 **F01** consola EC2 con las dos instancias *running*.
2. Conexión: `ssh -i llave.pem ubuntu@FRONT_PUB` y para el backend `ssh -i llave.pem -J ubuntu@FRONT_PUB ubuntu@10.0.128.10` (ProxyJump, como en el proyecto anterior).
3. Sube el código nuevo a los dos repositorios de GitHub (copia las carpetas del zip encima de tu clon, `git add -A`, `git commit`, `git push`). Revisa que **no** subas ningún `.env` ni `agente.env` con valores reales.

## 1. ec2-backend: preparar e instalar Snort (rúbrica 10% + 15%)

El backend no tiene internet. Igual que en el proyecto Zero Trust, se habilita **temporalmente** la salida para instalar paquetes:

1. VPC → rt-backend → agregar `0.0.0.0/0 → igw-backend` (reasocia el IGW a vpc-backend si lo quitaste). 📸 **F02** tabla de rutas temporal.
2. En ec2-backend:
   ```bash
   cat /etc/os-release && ip -br address && ip route && sudo whoami     # 📸 F03 (identifica la interfaz: eth0 en t2, ens5 en t3)
   sudo apt update && sudo apt upgrade -y
   sudo apt install -y snort snort-rules-default tcpdump ethtool acl nano tshark   # tshark: alerta 2 (sniffer)
   ```
   El asistente pregunta interfaz (`eth0`) y red local (`10.0.128.0/24`, la subred que muestra `ip route`). 📸 **F04** pantalla del asistente.
   Aprovecha que hay salida a internet para tres cosas más (todas en la carpeta del backend):
   ```bash
   git pull                                   # código nuevo
   npm ci --omit=dev                          # instala la dependencia nueva "pg" (driver de PostgreSQL)
   sudo bash db/instalar-postgresql.sh        # PostgreSQL + swap de 1 GB; imprime la DATABASE_URL   📸 F04b
   ```
3. Verifica: `snort -V` 📸 **F05** · `ls -la /etc/snort /etc/snort/rules /var/log/snort` 📸 **F06**.
4. Quita la ruta `0.0.0.0/0` de rt-backend (y desasocia el IGW). 📸 **F07** tabla de rutas final (solo local + peering). Esto es una *incidencia controlada*: anótala en la memoria.

## 2. ec2-backend: configurar Snort (rúbrica 20% + 15%)

```bash
mkdir -p ~/respaldo && sudo cp /etc/snort/snort.conf ~/respaldo/snort.conf.$(date +%F)
sudo cp /etc/snort/snort.debian.conf ~/respaldo/snort.debian.conf.$(date +%F)
sudo nano /etc/snort/snort.conf
```
Aplica lo de `atalaya-backend/ids/snort/snort.conf.fragmento` (HOME_NET `10.0.128.0/24`, EXTERNAL_NET `!$HOME_NET`,
`include $RULE_PATH/local.rules`, `output alert_fast: alert_fast.txt`, `config umask: 022`, `config checksum_mode: none`).

```bash
grep -nE 'ipvar HOME_NET|ipvar EXTERNAL_NET|var RULE_PATH|local.rules|alert_fast' /etc/snort/snort.conf   # 📸 F08
sudo nano /etc/snort/snort.debian.conf      # como snort.debian.conf.ejemplo (interfaz y HOME_NET iguales)   📸 F09
```
Reglas locales (6 reglas, objetivos 1, 2, 3 y ampliación):
```bash
cd CARPETA_DEL_BACKEND            # ya actualizada con git pull en el paso 1
sudo cp ids/snort/local.rules /etc/snort/rules/local.rules
cat /etc/snort/rules/local.rules            # 📸 F10
sudo snort -T -c /etc/snort/snort.conf -i eth0    # 📸 F11 "Snort successfully validated the configuration!"
```
**Demostrar que `local.rules` se carga (lo pide la 2.5):** borra el `;` final de una regla con `sudo nano /etc/snort/rules/local.rules`,
repite `snort -T` (📸 error que cita `local.rules` y la línea), restaura el `;` y valida otra vez (📸).
Si -T falla, **captura el error y su corrección** (vale para "incidencias" en la rúbrica).

Prueba en consola **antes** del servicio (requisito 6.6):
```bash
sudo systemctl stop snort       # para no duplicar instancias
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
# en otra terminal, desde ec2-frontend:  ping -c 4 10.0.128.10        📸 F12 alerta [1:1000001:1] en consola junto al ping
```
Servicio (requisito 6.7):
```bash
sudo systemctl enable --now snort && sudo systemctl restart snort
sudo systemctl status snort --no-pager      # 📸 F13 active (running) y "-i eth0" en la línea de comando
sudo journalctl -u snort -n 50 --no-pager   # 📸 F14
ps -ef | grep [s]nort                       # confirma -i eth0 y HOME_NET
systemctl is-enabled snort                  # debe decir enabled
sudo tail -n 20 /var/log/snort/alert_fast.txt
```
Atajo de transcripciones: `bash ids/snort/evidencias-snort.sh eth0` (desde la carpeta del backend) guarda todas las salidas en `~/evidencias/`.

## 3. ec2-backend: actualizar la API

1. Agrega al `.env` **existente** (no uses `npm run setup --force`: cambiaría las contraseñas y el JWT)
   la `DATABASE_URL` que imprimió `instalar-postgresql.sh` y las variables IDS de `.env.example`, con:
   ```bash
   openssl rand -hex 32        # -> pégala como IDS_INGEST_KEY (y guárdala para el agente)
   ```
   y `IDS_SNORT_INTERFACE=eth0`, `IDS_FRONTEND_PUBLIC_IP=FRONT_PUB`.
   Opcional (portal del cliente): genera el hash con `npm run hash -- "ContraseñaCliente"` y agrega
   `CLIENT_USERNAME=cliente`, `CLIENT_DISPLAY_NAME=Tienda Demo`, `CLIENT_PASSWORD_HASH='…'` (ver `SERVICIO.md`).
2. Crea las tablas y revisa: `npm run db:migrate` (la API también lo hace sola al arrancar). 📸 F14b la lista de tablas.
   Respaldo diario: sigue las 2 líneas de instalación al inicio de `db/respaldo-postgresql.sh`.
3. `sudo bash ids/snort/permisos-snort.sh` (lectura de `/var/log/snort/alert_fast.txt` para el usuario de la API).
4. `sudo systemctl restart atalaya-backend && sudo journalctl -u atalaya-backend -n 5` → debe decir `Almacenamiento: PostgreSQL 16…`.
5. En el sitio, **Sensores y reglas → Almacenamiento** muestra PostgreSQL como persistente. 📸 F20b.
6. Consultas para la memoria (alertas por sensor, accesos, fuerza bruta): `psql "$DATABASE_URL" -f db/consultas.sql`. 📸 F34b.

## 4. ec2-frontend: instalar y configurar Suricata

```bash
cat /etc/os-release && ip -br address && ip route                       # 📸 F15
sudo add-apt-repository -y ppa:oisf/suricata-stable && sudo apt update
sudo apt install -y suricata jq tcpdump ethtool nmap
suricata --build-info | head -n 5                                         # 📸 F16
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
sudo nano /etc/suricata/suricata.yaml     # aplica ids/suricata/suricata.yaml.fragmento.yaml
cd ~/atalaya-frontend && git pull
sudo cp ids/suricata/sensor*.rules /var/lib/suricata/rules/
sudo suricata-update
sudo ethtool -K ens5 gro off lro off
sudo suricata -T -c /etc/suricata/suricata.yaml -v                        # 📸 F17
sudo systemctl enable --now suricata && sudo systemctl restart suricata
sudo systemctl status suricata --no-pager                                 # 📸 F18
```

## 5. ec2-frontend: publicar el sitio nuevo y bloquear /api/internal

```bash
npm ci && npm run build
grep -n "root" /etc/nginx/sites-enabled/*          # carpeta donde publican el sitio
sudo rsync -a --delete dist/ /RUTA/DEL/ROOT/
sudo nano /etc/nginx/sites-available/atalaya        # pega ids/nginx/atalaya-internal.conf antes de location /api/
sudo nginx -t && sudo systemctl reload nginx
```
Abre `https://atalaya-zt.duckdns.org` → 📸 **F19** login nuevo · 📸 **F20** Centro de monitoreo.

## 6. Bot de Telegram y agente

1. En Telegram, **@BotFather** → `/newbot` → guarda el token (no lo pongas en el código ni en capturas).
2. Agrega el bot al grupo del equipo y escribe `/start@NombreDeTuBot` en el grupo.
3. En tu navegador: `https://api.telegram.org/botTOKEN/getUpdates` → busca `"chat":{"id":-100…}` → ese es el `TELEGRAM_CHAT_ID`.
4. En ec2-frontend:
   ```bash
   sudo mkdir -p /opt/atalaya /etc/atalaya
   sudo cp ids/agente/atalaya_agente.py /opt/atalaya/
   sudo cp ids/agente/agente.env.example /etc/atalaya/agente.env && sudo chmod 600 /etc/atalaya/agente.env
   sudo nano /etc/atalaya/agente.env        # IDS_INGEST_KEY del backend, token y chat id
   sudo cp ids/agente/atalaya-agente.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now atalaya-agente
   sudo journalctl -u atalaya-agente -f     # 📸 F21 "Conectado al backend"; en el grupo llega "el agente IDS se inició"
   ```
5. Prueba en el grupo: `/estado`, `/ultimas` y `/accesos`; inicia sesión en el sitio y verifica que llegue el aviso de acceso. 📸 **F22**.

## 7. Excepciones temporales de laboratorio (sin esto no llegan los ataques)

| Grupo | Regla temporal | Para qué |
|---|---|---|
| frontend-sg (entrada) | ICMP, TCP 1-1000 desde `KALI_IP/32` | ping, nmap, curl y sqlmap desde Kali hacia Suricata |
| frontend-sg (salida) | Todo TCP hacia `10.0.128.10/32` | nmap desde el frontend (pivote) al backend |
| backend-sg (entrada) | Todo TCP desde `10.0.0.10/32` | que los SYN del escaneo lleguen a la interfaz que vigila Snort |
| Fail2Ban | `ignoreip = KALI_IP` en el jail `nginx-atalaya-login` | que no los bloquee a media demo |

📸 **F23** las reglas temporales. Explica en la memoria que **el Security Group filtra antes de la interfaz**: si bloquea el paquete, el IDS nunca lo ve.

## 8. Pruebas (fase de caja blanca) y capturas de las alertas

Abre en el sitio **Demo en vivo**, escribe `FRONT_PUB`, pulsa **Iniciar demo** y sigue el guion (los comandos ya salen con las IP).
Por cada prueba toma: comando en Kali/terminal + alerta en `tail -f` del log + aviso en Telegram + paso marcado en verde.

| # | Prueba | Sensor / SID | Capturas |
|---|---|---|---|
| 1 | `ping -c 4 10.0.128.10` desde el frontend | Snort 1000001 | 📸 comando + alerta |
| 2 | En el backend `tshark -n` (control, sin alerta) y `tshark -N nN` (con alerta) mientras el frontend hace ping | Snort 1000002 | 📸 las dos ejecuciones + alerta |
| 3 | `sudo nmap -sS -p 1-200 10.0.128.10` desde el frontend | Snort 1000003 | 📸 comando + alerta |
| S1 | Kali: `ping -c 10`, `nmap -sS -p 1-1000`, `nmap -sV -sC -p 80` al frontend | Suricata 1000001-1000003 | 📸 fast.log |
| S2 | Kali: POST de login por HTTP + `tcpdump` + Wireshark + `suricata -r lab.pcap` | Suricata 1000100 (y 1000102 al iniciar sesión en el sitio) | 📸 Follow TCP Stream + fast.log |
| S3 | Kali: sqlmap normal y con `--random-agent` | Suricata 1000200-1000203 | 📸 fast.log de ambas |
| + | Login en el sitio (tramo interno en claro) y fuerza bruta | Snort 1000004, 1000005 | 📸 |

Logs para las capturas: `sudo tail -f /var/log/snort/alert_fast.txt` (backend) y `sudo tail -f /var/log/suricata/fast.log` (frontend).
Resumen con jq: `sudo jq -r 'select(.event_type=="alert") | .alert.signature' /var/log/suricata/eve.json | sort | uniq -c | sort -nr` 📸 **F34**.
En el sitio: **Alertas en vivo** → selecciona una alerta de cada prueba → 📸 **F35–F37** (el panel ya responde "qué tráfico la provocó, qué regla la generó y por qué era esperable").

## 9. Al terminar

Borra las excepciones de la tabla del punto 7, quita `KALI_IP` de `ignoreip`, y detén las instancias para no gastar crédito. 📸 **F38** Security Groups restaurados.

## Problemas frecuentes

| Síntoma | Causa probable y solución |
|---|---|
| `snort -T` falla con un archivo de reglas | Una regla mal escrita o un include a un archivo que no existe. El error indica archivo y línea. |
| Snort funciona en consola pero no como servicio | La interfaz o HOME_NET de `snort.debian.conf` no coinciden con `snort.conf`. Revisa `journalctl -u snort`. |
| El ping no genera alerta | El SG no permite ICMP, la interfaz es otra (eth0/ens5) o HOME_NET no incluye la IP destino. Confirma con `sudo tcpdump -i eth0 icmp`. |
| Nmap no alerta en Snort | backend-sg solo deja pasar el 3000: falta la excepción "todo TCP desde 10.0.0.10". |
| La API no arranca: "No se pudo iniciar la API… DATABASE_URL" | PostgreSQL detenido (`systemctl status postgresql`) o contraseña/URL distinta a la que imprimió el script. |
| "Cannot find package 'pg'" | Falta `npm ci --omit=dev` en el backend (hazlo en la ventana con internet). |
| La tarjeta de Snort dice "Sin permiso de lectura" | Ejecuta `sudo bash ids/snort/permisos-snort.sh`. |
| La tarjeta de Suricata dice "Esperando al agente" | `systemctl status atalaya-agente`; revisa `IDS_INGEST_KEY` (debe ser igual en los dos servidores). |
| No llegan mensajes a Telegram | Token o chat id incorrectos (el de grupo es negativo); el agente lo muestra en `journalctl -u atalaya-agente`. |
| sqlmap se detiene por la redirección a HTTPS | Usa `--ignore-redirects` (ya viene en el guion); las cargas igual pasan por el puerto 80 que vigila Suricata. |
