export class GetAuditLog {
  constructor({ auditLog }) {
    this.auditLog = auditLog;
  }

  async execute({ limit, type }) {
    const events = await this.auditLog.recent({ limit, type });
    return { total: events.length, events };
  }
}
