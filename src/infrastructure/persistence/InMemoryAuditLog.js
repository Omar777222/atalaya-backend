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
  }

  async record(event) {
    this.events.push(event);
    if (this.events.length > this.maxEvents) this.events.shift();
    this.writer(JSON.stringify({ source: 'atalaya-api', ...event }));
  }

  async recent({ limit = 50, type } = {}) {
    const filtered = type ? this.events.filter((e) => e.type === type) : this.events;
    return filtered.slice(-limit).reverse(); // más recientes primero
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
