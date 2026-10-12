// Lista de tokens cerrados antes de expirar (cierre de sesión real).
export class RevokedTokenStore {
  async revoke(_jti, _expiresAt) { throw new Error('No implementado'); }
  async isRevoked(_jti) { throw new Error('No implementado'); }
}
