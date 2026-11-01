import { IdsAlertStore } from '../../domain/ports/IdsAlertStore.js';

// Guarda las últimas alertas en memoria. Cada alerta recibe un número consecutivo (cursor)
// que usan el sitio y el bot de Telegram para pedir "solo lo nuevo".
export class InMemoryIdsAlertStore extends IdsAlertStore {
  constructor({ maxAlerts = 5000 } = {}) {
    super();
    this.maxAlerts = maxAlerts;
    this.alerts = [];
    this.seq = 0;
  }

  async add(alerts) {
    const stored = alerts.map((a) => {
      this.seq += 1;
      return Object.freeze({ ...a, seq: this.seq, id: `${a.sensor}-${this.seq}` });
    });
    this.alerts.push(...stored);
    if (this.alerts.length > this.maxAlerts) this.alerts.splice(0, this.alerts.length - this.maxAlerts);
    return stored;
  }

  async list({ sensor, objective, after = 0, limit = 100 } = {}) {
    const out = [];
    for (let i = this.alerts.length - 1; i >= 0 && out.length < limit; i -= 1) {
      const a = this.alerts[i];
      if (a.seq <= after) break;
      if (sensor && a.sensor !== sensor) continue;
      if (objective && a.objective !== objective) continue;
      out.push(a);
    }
    return out; // más recientes primero
  }

  async all() {
    return this.alerts;
  }

  async latestCursor() {
    return this.seq;
  }

  async clear(_opts = {}) {
    this.alerts = [];
    // El cursor NO se reinicia: así el bot nunca recibe dos veces el mismo número.
  }
}
