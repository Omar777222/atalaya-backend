import { createHash } from 'node:crypto';
import { IdsAlertStore } from '../../../domain/ports/IdsAlertStore.js';
import { toIso } from './database.js';

const COLUMNS = 'sensor, ts, gid, sid, rev, message, classification, priority, protocol, src_ip, src_port, dst_ip, dst_port, objective, local_rule, raw, extra, fingerprint';

const fingerprintOf = (a) => createHash('sha256')
  .update(`${a.sensor}|${a.raw ?? JSON.stringify([a.timestamp, a.sid, a.srcIp, a.srcPort, a.dstIp, a.dstPort])}`)
  .digest('hex');

const toAlert = (r) => Object.freeze({
  sensor: r.sensor, timestamp: toIso(r.ts), gid: r.gid, sid: r.sid, rev: r.rev, message: r.message,
  classification: r.classification, priority: r.priority, protocol: r.protocol,
  srcIp: r.src_ip, srcPort: r.src_port, dstIp: r.dst_ip, dstPort: r.dst_port,
  objective: r.objective, localRule: r.local_rule, raw: r.raw,
  extra: typeof r.extra === 'string' ? JSON.parse(r.extra) : r.extra,
  seq: Number(r.id), id: `${r.sensor}-${r.id}`,
});

// Histórico de alertas en PostgreSQL. El panel trabaja con "lo posterior al último reinicio"
// (ids_resets) y los últimos 7 días; el histórico completo queda en la tabla para reportes.
export class PostgresIdsAlertStore extends IdsAlertStore {
  constructor(pool, { windowDays = 7, maxRows = 5000 } = {}) {
    super();
    Object.assign(this, { pool, windowDays, maxRows });
    this.baseline = 0;
  }

  async init() {
    const { rows } = await this.pool.query('SELECT coalesce(max(cursor), 0) AS c FROM ids_resets');
    this.baseline = Number(rows[0].c);
  }

  async add(alerts) {
    const stored = [];
    for (const a of alerts) {
      const { rows } = await this.pool.query(
        `INSERT INTO ids_alerts (${COLUMNS})
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
         ON CONFLICT (fingerprint) DO NOTHING RETURNING *`,
        [a.sensor, a.timestamp, a.gid, a.sid, a.rev, a.message, a.classification, a.priority, a.protocol,
          a.srcIp, a.srcPort, a.dstIp, a.dstPort, a.objective, a.localRule, a.raw,
          a.extra ? JSON.stringify(a.extra) : null, fingerprintOf(a)],
      );
      if (rows[0]) stored.push(toAlert(rows[0])); // si ya existía (relectura del log) no se duplica
    }
    return stored;
  }

  async list({ sensor, objective, after = 0, limit = 100 } = {}) {
    const { rows } = await this.pool.query(
      `SELECT * FROM ids_alerts
       WHERE id > $1 AND ($2::text IS NULL OR sensor = $2) AND ($3::text IS NULL OR objective = $3)
       ORDER BY id DESC LIMIT $4`,
      [Math.max(after ?? 0, this.baseline), sensor ?? null, objective ?? null, limit],
    );
    return rows.map(toAlert);
  }

  async all() {
    const { rows } = await this.pool.query(
      `SELECT * FROM (
         SELECT * FROM ids_alerts WHERE id > $1 AND ts >= now() - make_interval(days => $2)
         ORDER BY id DESC LIMIT $3
       ) t ORDER BY id`,
      [this.baseline, this.windowDays, this.maxRows],
    );
    return rows.map(toAlert);
  }

  async latestCursor() {
    const { rows } = await this.pool.query('SELECT coalesce(max(id), 0) AS c FROM ids_alerts');
    return Number(rows[0].c);
  }

  // No borra: registra el reinicio para que el panel empiece de cero y el histórico se conserve
  async clear({ by = null } = {}) {
    const cursor = await this.latestCursor();
    await this.pool.query('INSERT INTO ids_resets (cursor, reset_by) VALUES ($1, $2)', [cursor, by]);
    this.baseline = cursor;
  }

  async count() {
    const { rows } = await this.pool.query('SELECT count(*) AS n, min(ts) AS first FROM ids_alerts');
    return { total: Number(rows[0].n), since: toIso(rows[0].first) };
  }
}
