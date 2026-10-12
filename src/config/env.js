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

if (config.jwt.secret.length < 32) {
  throw new Error('JWT_SECRET debe tener al menos 32 caracteres');
}
