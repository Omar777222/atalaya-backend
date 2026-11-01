// Puerto: dónde se guardan las alertas de los dos sensores.
export class IdsAlertStore {
  async add(_alerts) { throw new Error('No implementado'); }
  async list({ sensor, objective, after, limit } = {}) { throw new Error('No implementado'); }
  async all() { throw new Error('No implementado'); }
  async latestCursor() { throw new Error('No implementado'); }
  async clear() { throw new Error('No implementado'); }
}
