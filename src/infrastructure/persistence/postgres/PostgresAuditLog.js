import { AuditLog } from '../../../domain/ports/AuditLog.js';
import { SecurityEventTypes } from '../../../domain/entities/SecurityEvent.js';
import { toIso } from './database.js';

const toEvent = (r) => Object.freeze({
  id: r.event_id, seq: Number(r.id), timestamp: toIso(r.ts), type: r.type, severity: r.severity,
  username: r.username, ip: r.ip, path: r.path, detail: r.detail, requestId: r.request_id,
});

// Auditoría persistente: los eventos sobreviven a reinicios y quedan para el análisis posterior.
export class PostgresAuditLog extends AuditLog {
  constructor(pool, { writer = console.log } = {}) {
    super();
    this.pool = pool;
    this.writer = writer;
  }

  async record(e) {
    await this.pool.query(
      `INSERT INTO audit_events (event_id, ts, type, severity, username, ip, path, detail, request_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [e.id, e.timestamp, e.type, e.severity, e.username, e.ip, e.path, String(e.detail ?? '').slice(0, 500), e.requestId],
    );
    this.writer(JSON.stringify({ source: 'atalaya-api', ...e })); // también al journal (CloudWatch)
  }

  async recent({ limit = 50, type } = {}) {
    const { rows } = await this.pool.query(
      'SELECT * FROM audit_events WHERE ($1::text IS NULL OR type = $1) ORDER BY id DESC LIMIT $2',
      [type ?? null, limit],
    );
    return rows.map(toEvent);
  }

  async summary({ sinceMs = 24 * 60 * 60 * 1000 } = {}) {
    const { rows } = await this.pool.query(
      'SELECT type, count(*) AS n FROM audit_events WHERE ts >= $1 GROUP BY type',
      [new Date(Date.now() - sinceMs).toISOString()],
    );
    const counts = Object.fromEntries(Object.keys(SecurityEventTypes).map((t) => [t, 0]));
    for (const r of rows) counts[r.type] = Number(r.n);
    return counts;
  }

  async feed({ after, limit = 50 } = {}) {
    if (after === undefined) {
      const { rows } = await this.pool.query('SELECT coalesce(max(id), 0) AS c FROM audit_events');
      return { cursor: Number(rows[0].c), events: [] };
    }
    const { rows } = await this.pool.query('SELECT * FROM audit_events WHERE id > $1 ORDER BY id LIMIT $2', [after, limit]);
    const events = rows.map(toEvent);
    return { cursor: events.at(-1)?.seq ?? after, events };
  }

  async count() {
    const { rows } = await this.pool.query('SELECT count(*) AS n FROM audit_events');
    return Number(rows[0].n);
  }
}
