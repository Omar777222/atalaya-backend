import { ForbiddenError } from '../../domain/errors/DomainErrors.js';
import { createSecurityEvent, SecurityEventTypes } from '../../domain/entities/SecurityEvent.js';

// Mínimo privilegio: cada recurso declara qué roles pueden usarlo.
export class AuthorizeAccess {
  constructor({ auditLog }) {
    this.auditLog = auditLog;
  }

  async execute({ user, allowedRoles, context }) {
    if (user.hasAnyRole(allowedRoles)) return;
    await this.auditLog.record(createSecurityEvent({
      type: SecurityEventTypes.ACCESS_DENIED, username: user.username, ...context,
      detail: `Rol ${user.role} sin permiso (requiere: ${allowedRoles.join(', ')})`,
    }));
    throw new ForbiddenError();
  }
}
