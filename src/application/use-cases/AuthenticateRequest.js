import { UnauthorizedError } from '../../domain/errors/DomainErrors.js';
import { createSecurityEvent, SecurityEventTypes } from '../../domain/entities/SecurityEvent.js';

// Zero Trust: se ejecuta en CADA petición protegida. Nunca se confía en una sesión previa.
export class AuthenticateRequest {
  constructor({ tokenService, revokedTokenStore, userRepository, auditLog }) {
    Object.assign(this, { tokenService, revokedTokenStore, userRepository, auditLog });
  }

  async execute({ token, context }) {
    try {
      if (!token) throw new UnauthorizedError('Falta el token de acceso');

      const claims = this.tokenService.verify(token); // 1. firma, emisor, audiencia y expiración
      if (await this.revokedTokenStore.isRevoked(claims.jti)) { // 2. no fue cerrado
        throw new UnauthorizedError('La sesión fue cerrada. Inicia sesión de nuevo.');
      }
      const user = await this.userRepository.findById(claims.userId); // 3. el usuario sigue activo
      if (!user) throw new UnauthorizedError('El usuario de esta sesión ya no está activo');

      return { user, session: { jti: claims.jti, issuedAt: claims.issuedAt, expiresAt: claims.expiresAt } };
    } catch (err) {
      await this.auditLog.record(createSecurityEvent({
        type: SecurityEventTypes.TOKEN_REJECTED, ...context, detail: err.message,
      }));
      throw err instanceof UnauthorizedError ? err : new UnauthorizedError();
    }
  }
}
