import { RevokedTokenStore } from '../../../domain/ports/RevokedTokenStore.js';

// Tokens cerrados antes de expirar: un logout sigue siendo válido aunque la API se reinicie.
export class PostgresRevokedTokenStore extends RevokedTokenStore {
  constructor(pool) {
    super();
    this.pool = pool;
  }

  async revoke(jti, expiresAt) {
    await this.pool.query('DELETE FROM revoked_tokens WHERE expires_at <= now()'); // limpieza
    await this.pool.query(
      'INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING',
      [jti, new Date(expiresAt).toISOString()],
    );
  }

  async isRevoked(jti) {
    const { rows } = await this.pool.query('SELECT 1 FROM revoked_tokens WHERE jti = $1 AND expires_at > now()', [jti]);
    return rows.length > 0;
  }
}
