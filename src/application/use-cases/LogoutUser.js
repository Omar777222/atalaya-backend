import { createSecurityEvent, SecurityEventTypes } from '../../domain/entities/SecurityEvent.js';

// El token se invalida en el servidor: aunque alguien lo copie, ya no sirve.
export class LogoutUser {
  constructor({ revokedTokenStore, auditLog }) {
    Object.assign(this, { revokedTokenStore, auditLog });
  }

  async execute({ user, session, context }) {
    await this.revokedTokenStore.revoke(session.jti, session.expiresAt);
    await this.auditLog.record(createSecurityEvent({
      type: SecurityEventTypes.LOGOUT, username: user.username, ...context, detail: 'Token revocado',
    }));
  }
}
