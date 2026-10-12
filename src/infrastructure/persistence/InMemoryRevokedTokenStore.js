import { RevokedTokenStore } from '../../domain/ports/RevokedTokenStore.js';

export class InMemoryRevokedTokenStore extends RevokedTokenStore {
  constructor() {
    super();
    this.revoked = new Map(); // jti -> fecha de expiración (ms)
  }

  #purgeExpired() {
    const now = Date.now();
    for (const [jti, exp] of this.revoked) if (exp <= now) this.revoked.delete(jti);
  }

  async revoke(jti, expiresAt) {
    this.#purgeExpired();
    this.revoked.set(jti, new Date(expiresAt).getTime());
  }

  async isRevoked(jti) {
    this.#purgeExpired();
    return this.revoked.has(jti);
  }
}
