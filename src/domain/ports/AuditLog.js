export class AuditLog {
  async record(_event) { throw new Error('No implementado'); }
  async recent({ limit, type } = {}) { throw new Error('No implementado'); }
  async summary({ sinceMs } = {}) { throw new Error('No implementado'); }
}
