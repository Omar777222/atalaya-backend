import { UserRepository } from '../../../domain/ports/UserRepository.js';
import { ClientRepository } from '../../../domain/ports/ClientRepository.js';
import { User } from '../../../domain/entities/User.js';

const toUser = (r) => new User({
  id: r.id, username: r.username, displayName: r.display_name, role: r.role, passwordHash: r.password_hash, clientId: r.client_id,
});

// Usuarios en PostgreSQL. Todas las consultas son parametrizadas ($1): sin inyección SQL.
export class PostgresUserRepository extends UserRepository {
  constructor(pool) {
    super();
    this.pool = pool;
  }

  async findByUsername(username) {
    const { rows } = await this.pool.query('SELECT * FROM users WHERE username = $1 AND active', [username]);
    return rows[0] ? toUser(rows[0]) : null;
  }

  async findById(id) {
    if (!/^\d+$/.test(String(id))) return null;
    const { rows } = await this.pool.query('SELECT * FROM users WHERE id = $1 AND active', [Number(id)]);
    return rows[0] ? toUser(rows[0]) : null;
  }

  // Los usuarios de demostración se siguen definiendo en el .env (hash bcrypt) y se sincronizan al arrancar.
  async seed(users, clientId) {
    for (const u of users) {
      await this.pool.query(
        `INSERT INTO users (username, display_name, role, password_hash, client_id)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (username) DO UPDATE SET display_name = EXCLUDED.display_name, role = EXCLUDED.role,
           password_hash = EXCLUDED.password_hash, client_id = EXCLUDED.client_id, updated_at = now()`,
        [u.username, u.displayName, u.role, u.passwordHash, u.role === 'client' ? clientId : null],
      );
    }
  }
}

export class PostgresClientRepository extends ClientRepository {
  constructor(pool) {
    super();
    this.pool = pool;
  }

  async findById(id) {
    if (!/^\d+$/.test(String(id ?? ''))) return null;
    const { rows } = await this.pool.query('SELECT id, name, site, plan, contact FROM clients WHERE id = $1', [Number(id)]);
    return rows[0] ?? null;
  }

  // Crea (o actualiza) la empresa cliente de la demo y devuelve su id
  async seed({ name, site, plan, contact }) {
    const { rows } = await this.pool.query(
      `INSERT INTO clients (name, site, plan, contact) VALUES ($1, $2, $3, $4)
       ON CONFLICT (site) DO UPDATE SET name = EXCLUDED.name, plan = EXCLUDED.plan, contact = EXCLUDED.contact
       RETURNING id`,
      [name, site, plan, contact],
    );
    return Number(rows[0].id);
  }
}
