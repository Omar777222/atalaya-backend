import { AuditLog } from '../../domain/ports/AuditLog.js';
import { SecurityEventTypes } from '../../domain/entities/SecurityEvent.js';

// Guarda los últimos eventos en memoria y además los imprime como JSON
// (en AWS quedan en el journal del servicio y se pueden enviar a CloudWatch).
export class InMemoryAuditLog extends AuditLog {
  constructor({ maxEvents = 500, writer = console.log } = {}) {
    super();
    this.maxEvents = maxEvents;
    this.writer = writer;
    this.events = [];
    this.seq = 0; // número consecutivo: el bot de Telegram pide "solo lo nuevo"
  }

  async record(event) {
    this.seq += 1;
    event = Object.freeze({ ...event, seq: this.seq });
    this.events.push(event);
    if (this.events.length > this.maxEvents) this.events.shift();
    this.writer(JSON.stringify({ source: 'atalaya-api', ...event }));
  }

  async recent({ limit = 50, type } = {}) {
    const filtered = type ? this.events.filter((e) => e.type === type) : this.events;
    return filtered.slice(-limit).reverse(); // más recientes primero
  }

  // Eventos posteriores al cursor, en orden cronológico (para el bot)
  async feed({ after, limit = 50 } = {}) {
    if (after === undefined) return { cursor: this.seq, events: [] };
    const events = this.events.filter((e) => e.seq > after).slice(0, limit);
    return { cursor: events.at(-1)?.seq ?? Math.min(after, this.seq), events };
  }

  async summary({ sinceMs = 24 * 60 * 60 * 1000 } = {}) {
    const since = Date.now() - sinceMs;
    const counts = Object.fromEntries(Object.keys(SecurityEventTypes).map((t) => [t, 0]));
    for (const e of this.events) {
      if (new Date(e.timestamp).getTime() >= since) counts[e.type] += 1;
    }
    return counts;
  }
}
