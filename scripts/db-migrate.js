// Aplica db/schema.sql a la base de datos de DATABASE_URL (la API también lo hace al arrancar).
// Uso: npm run db:migrate
import 'dotenv/config';
import { openDatabase, migrate } from '../src/infrastructure/persistence/postgres/database.js';

if (!process.env.DATABASE_URL) {
  console.error('Falta DATABASE_URL en el .env (postgres://atalaya:CONTRASEÑA@127.0.0.1:5432/atalaya)');
  process.exit(1);
}
const pool = await openDatabase({ url: process.env.DATABASE_URL, max: 1 });
await migrate(pool);
const { rows } = await pool.query("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY 1");
console.log('Esquema aplicado. Tablas:', rows.map((r) => r.table_name).join(', '));
await pool.end();
