import 'dotenv/config';

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Falta la variable ${name} en el .env. Ejecuta: npm run setup -- "ContraseñaAdmin" "ContraseñaAnalista"`);
  }
  return value;
}

export const config = {
  port: Number(process.env.PORT ?? 3000),
  host: process.env.HOST ?? '127.0.0.1',
  trustProxy: process.env.TRUST_PROXY ?? 'loopback',
  jwt: {
    secret: required('JWT_SECRET'),
    expiresIn: process.env.JWT_EXPIRES_IN ?? '15m',
    issuer: process.env.JWT_ISSUER ?? 'atalaya-api',
    audience: process.env.JWT_AUDIENCE ?? 'atalaya-web',
  },
  users: [
    {
      id: '1',
      username: process.env.ADMIN_USERNAME ?? 'admin',
      displayName: 'Administración',
      role: 'admin',
      passwordHash: required('ADMIN_PASSWORD_HASH'),
    },
    {
      id: '2',
      username: process.env.ANALYST_USERNAME ?? 'analista',
      displayName: 'Analista de seguridad',
      role: 'analyst',
      passwordHash: required('ANALYST_PASSWORD_HASH'),
    },
  ],
};

// Cliente del servicio (opcional): existe solo si npm run setup recibió una tercera contraseña
if (process.env.CLIENT_PASSWORD_HASH) {
  config.users.push({
    id: '3',
    username: process.env.CLIENT_USERNAME ?? 'cliente',
    displayName: process.env.CLIENT_DISPLAY_NAME ?? 'Tienda Demo (cliente)',
    role: 'client',
    passwordHash: process.env.CLIENT_PASSWORD_HASH,
  });
}

// Base de datos: con DATABASE_URL se usa PostgreSQL; sin ella, memoria (desarrollo y respaldo)
config.db = {
  url: process.env.DATABASE_URL || null,
  poolMax: Number(process.env.DATABASE_POOL_MAX ?? 5),
};

// Datos del servicio que ve el cliente en "Mi sitio"
config.service = {
  name: process.env.SERVICE_NAME ?? 'Atalaya SOC',
  plan: process.env.SERVICE_PLAN ?? 'Profesional',
  clientName: process.env.CLIENT_DISPLAY_NAME ?? 'Tienda Demo',
  site: process.env.IDS_DOMAIN ?? 'atalaya-zt.duckdns.org',
  contact: process.env.SERVICE_CONTACT ?? 'Grupo de Telegram del equipo de seguridad',
};

if (config.jwt.secret.length < 32) {
  throw new Error('JWT_SECRET debe tener al menos 32 caracteres');
}

const env = (name, fallback) => process.env[name] || fallback;

// ---------- IDS: Snort en este servidor (backend) y Suricata en el frontend ----------
config.ids = {
  ingestKey: required('IDS_INGEST_KEY'),
  snort: {
    alertFile: env('IDS_SNORT_ALERT_FILE', '/var/log/snort/alert_fast.txt'),
    service: env('IDS_SNORT_SERVICE', 'snort'),
  },
  sensors: {
    suricata: {
      id: 'suricata',
      name: 'Suricata',
      kind: 'NIDS',
      role: 'Vigila la red del frontend: todo lo que llega desde internet',
      host: 'ec2-frontend',
      ip: env('IDS_FRONTEND_PRIVATE_IP', '10.0.0.10'),
      os: env('IDS_SURICATA_OS', 'Ubuntu Server'),
      interface: env('IDS_SURICATA_INTERFACE', 'ens5'),
      homeNet: env('IDS_SURICATA_HOME_NET', '10.0.0.0/17'),
      externalNet: '!$HOME_NET',
      configFile: '/etc/suricata/suricata.yaml',
      ruleFiles: ['atalaya-obj1-icmp.rules', 'atalaya-obj2-wireshark.rules', 'atalaya-obj3-nmap.rules', 'atalaya-extra-sqlmap.rules'],
      ruleDir: '/var/lib/suricata/rules',
      logFiles: ['/var/log/suricata/fast.log', '/var/log/suricata/eve.json'],
      testCommand: 'sudo suricata -T -c /etc/suricata/suricata.yaml -v',
      serviceCommand: 'sudo systemctl status suricata --no-pager',
    },
    snort: {
      id: 'snort',
      name: 'Snort',
      kind: 'HIDS',
      role: 'Vigila el propio servidor del backend: lo que cruza el peering',
      host: 'ec2-backend',
      ip: env('IDS_BACKEND_PRIVATE_IP', '10.0.128.10'),
      os: env('IDS_SNORT_OS', 'Ubuntu Server'),
      interface: env('IDS_SNORT_INTERFACE', 'eth0'),
      homeNet: env('IDS_SNORT_HOME_NET', '10.0.128.0/17'),
      externalNet: '!$HOME_NET',
      configFile: '/etc/snort/snort.conf',
      ruleFiles: ['local.rules'],
      ruleDir: '/etc/snort/rules',
      logFiles: [env('IDS_SNORT_ALERT_FILE', '/var/log/snort/alert_fast.txt')],
      testCommand: `sudo snort -T -c /etc/snort/snort.conf -i ${env('IDS_SNORT_INTERFACE', 'eth0')}`,
      serviceCommand: 'sudo systemctl status snort --no-pager',
    },
  },
  // IPs que se sustituyen en los comandos de la "Demo en vivo"
  targets: {
    frontendPublicIp: env('IDS_FRONTEND_PUBLIC_IP', 'IP_PUBLICA_FRONTEND'),
    frontendPrivateIp: env('IDS_FRONTEND_PRIVATE_IP', '10.0.0.10'),
    backendPrivateIp: env('IDS_BACKEND_PRIVATE_IP', '10.0.128.10'),
    domain: env('IDS_DOMAIN', 'atalaya-zt.duckdns.org'),
    frontendHomeNet: env('IDS_SURICATA_HOME_NET', '10.0.0.0/17'),
  },
};

if (config.ids.ingestKey.length < 32) {
  throw new Error('IDS_INGEST_KEY debe tener al menos 32 caracteres');
}
