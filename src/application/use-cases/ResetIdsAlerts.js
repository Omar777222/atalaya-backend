import { createSecurityEvent, SecurityEventTypes } from '../../domain/entities/SecurityEvent.js';

// Deja los contadores en cero antes de la demostración. Solo administración y queda auditado.
export class ResetIdsAlerts {
  constructor({ alertStore, auditLog }) {
    Object.assign(this, { alertStore, auditLog });
  }

  async execute({ user, context }) {
    const before = (await this.alertStore.all()).length;
    await this.alertStore.clear({ by: user.username });
    await this.auditLog.record(createSecurityEvent({
      type: SecurityEventTypes.IDS_RESET, username: user.username, ...context,
      detail: `Se reiniciaron los contadores del IDS (${before} alertas en memoria)`,
    }));
    return { cleared: before };
  }
}
