import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCHEMA = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../db/schema.sql');

// Abre el pool de conexiones. "pg" se carga solo si hay DATABASE_URL:
// así el modo en memoria (desarrollo) no necesita PostgreSQL instalado.
export async function openDatabase({ url, max = 5 }) {
  const { default: pg } = await import('pg');
  const pool = new pg.Pool({
    connectionString: url,
    max,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    application_name: 'atalaya-api',
  });
  pool.on('error', (err) => console.error(JSON.stringify({ source: 'atalaya-api', level: 'error', message: `PostgreSQL: ${err.message}` })));
  await pool.query('SELECT 1'); // falla rápido si la URL, el usuario o la contraseña están mal
  return pool;
}

// Aplica db/schema.sql (CREATE ... IF NOT EXISTS): seguro de ejecutar en cada arranque
export async function migrate(pool) {
  await pool.query(await readFile(SCHEMA, 'utf8'));
}

export const toIso = (v) => (v ? new Date(v).toISOString() : null);
