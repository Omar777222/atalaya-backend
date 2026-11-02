// Genera el archivo .env con un secreto JWT aleatorio, las contraseñas cifradas con bcrypt
// y la clave que comparte el backend con el agente IDS del frontend.
// Uso: npm run setup -- "ContraseñaAdmin" "ContraseñaAnalista" ["ContraseñaCliente"] [opciones] [--force]
//   La tercera contraseña es opcional: crea el usuario "cliente" del servicio (portal Mi sitio).
//   --host 0.0.0.0            (AWS)   --trust-proxy 10.0.0.10   (IP privada del frontend)
//   --snort-file RUTA         (local: ./samples/alert_fast.txt)
//   --snort-iface ens5        (interfaz del backend: confírmala con ip -br address)
//   --public-ip 52.x.x.x      (IP pública del frontend para los comandos de la demo)
//   --database-url postgres://atalaya:CLAVE@127.0.0.1:5432/atalaya   (sin ella: modo memoria)
import { existsSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import bcrypt from 'bcryptjs';

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
};
const positional = args.filter((a, i) => !a.startsWith('--') && !args[i - 1]?.startsWith('--'));
const [adminPassword, analystPassword, clientPassword] = positional;

if (!adminPassword || !analystPassword) {
  console.error('Uso: npm run setup -- "ContraseñaAdmin" "ContraseñaAnalista"');
  process.exit(1);
}
for (const p of [adminPassword, analystPassword, clientPassword].filter(Boolean)) {
  if (p.length < 10) {
    console.error('Cada contraseña debe tener al menos 10 caracteres.');
    process.exit(1);
  }
}
if (existsSync('.env') && !args.includes('--force')) {
  console.error('Ya existe un .env. Usa --force si quieres reemplazarlo.');
  process.exit(1);
}

const ingestKey = randomBytes(32).toString('hex');

const env = `PORT=3000
HOST=${flag('--host', '127.0.0.1')}
TRUST_PROXY=${flag('--trust-proxy', 'loopback')}

# PostgreSQL (vacía = memoria)
DATABASE_URL=${flag('--database-url', '')}
DATABASE_POOL_MAX=5

JWT_SECRET=${randomBytes(48).toString('hex')}
JWT_EXPIRES_IN=15m
JWT_ISSUER=atalaya-api
JWT_AUDIENCE=atalaya-web

ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH='${bcrypt.hashSync(adminPassword, 12)}'
ANALYST_USERNAME=analista
ANALYST_PASSWORD_HASH='${bcrypt.hashSync(analystPassword, 12)}'
${clientPassword ? `CLIENT_USERNAME=cliente
CLIENT_DISPLAY_NAME=Tienda Demo
CLIENT_PASSWORD_HASH='${bcrypt.hashSync(clientPassword, 12)}'
SERVICE_NAME=Atalaya SOC
SERVICE_PLAN=Profesional
` : ''}
# ---------- IDS ----------
IDS_INGEST_KEY=${ingestKey}
IDS_SNORT_ALERT_FILE=${flag('--snort-file', '/var/log/snort/alert_fast.txt')}
IDS_SNORT_SERVICE=snort
IDS_SNORT_HOME_NET=10.0.128.0/24
IDS_SNORT_INTERFACE=${flag('--snort-iface', 'eth0')}
IDS_SURICATA_HOME_NET=10.0.0.0/17
IDS_SURICATA_INTERFACE=${flag('--suricata-iface', 'ens5')}
IDS_FRONTEND_PRIVATE_IP=10.0.0.10
IDS_BACKEND_PRIVATE_IP=10.0.128.10
IDS_FRONTEND_PUBLIC_IP=${flag('--public-ip', 'IP_PUBLICA_FRONTEND')}
IDS_DOMAIN=atalaya-zt.duckdns.org
`;

writeFileSync('.env', env, { mode: 0o600 });
console.log(`Archivo .env creado. Usuarios: admin, analista${clientPassword ? ' y cliente (portal Mi sitio)' : ''}.`);
console.log('\nIDS_INGEST_KEY (cópiala en /etc/atalaya/agente.env de ec2-frontend):');
console.log(ingestKey);
