// Eventos de auditoría nuevos (inicios de sesión, fallos, accesos denegados…) para el bot de Telegram.
export class GetAuditFeed {
  constructor({ auditLog }) {
    this.auditLog = auditLog;
  }

  execute({ after, limit = 50 }) {
    return this.auditLog.feed({ after, limit });
  }
}
