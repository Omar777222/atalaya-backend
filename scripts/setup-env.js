// Genera el archivo .env con un secreto JWT aleatorio y las contraseñas cifradas con bcrypt.
// Uso: npm run setup -- "ContraseñaAdmin" "ContraseñaAnalista" [--host 0.0.0.0] [--trust-proxy 10.0.0.10] [--force]
import { existsSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import bcrypt from 'bcryptjs';

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
};
const positional = args.filter((a, i) => !a.startsWith('--') && !args[i - 1]?.startsWith('--'));
const [adminPassword, analystPassword] = positional;

if (!adminPassword || !analystPassword) {
  console.error('Uso: npm run setup -- "ContraseñaAdmin" "ContraseñaAnalista"');
  process.exit(1);
}
for (const p of [adminPassword, analystPassword]) {
  if (p.length < 10) {
    console.error('Cada contraseña debe tener al menos 10 caracteres.');
    process.exit(1);
  }
}
if (existsSync('.env') && !args.includes('--force')) {
  console.error('Ya existe un .env. Usa --force si quieres reemplazarlo.');
  process.exit(1);
}

const env = `PORT=3000
HOST=${flag('--host', '127.0.0.1')}
TRUST_PROXY=${flag('--trust-proxy', 'loopback')}

JWT_SECRET=${randomBytes(48).toString('hex')}
JWT_EXPIRES_IN=15m
JWT_ISSUER=atalaya-api
JWT_AUDIENCE=atalaya-web

ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH='${bcrypt.hashSync(adminPassword, 12)}'
ANALYST_USERNAME=analista
ANALYST_PASSWORD_HASH='${bcrypt.hashSync(analystPassword, 12)}'
`;

writeFileSync('.env', env, { mode: 0o600 });
console.log('Archivo .env creado. Usuarios: admin (administración) y analista (solo lectura).');
