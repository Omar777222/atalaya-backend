import { execFile } from 'node:child_process';
import { SensorMonitor } from '../../domain/ports/SensorMonitor.js';
import { Sensors } from '../../domain/catalog/detectionCatalog.js';

// Snort corre en esta misma máquina (ec2-backend): se pregunta a systemd directamente.
// Suricata corre en ec2-frontend: su estado llega como "latido" que envía el agente.
function systemctlIsActive(unit) {
  return new Promise((resolve) => {
    execFile('systemctl', ['is-active', unit], { timeout: 2000 }, (err, stdout) => {
      if (err && err.code === 'ENOENT') return resolve('unavailable'); // no hay systemd (entorno local)
      resolve((stdout || '').trim() || 'unknown');
    });
  });
}

export class LocalAndRemoteSensorMonitor extends SensorMonitor {
  constructor({ snortUnit = 'snort', snortWatcher, heartbeatTtlMs = 90_000 }) {
    super();
    Object.assign(this, { snortUnit, snortWatcher, heartbeatTtlMs });
    this.heartbeats = new Map();
  }

  async heartbeat(sensor, data) {
    this.heartbeats.set(sensor, { ...data, receivedAt: new Date().toISOString() });
  }

  async status(sensor) {
    if (sensor === Sensors.SNORT) {
      const service = await systemctlIsActive(this.snortUnit);
      return { service, log: this.snortWatcher.describe(), lastHeartbeatAt: new Date().toISOString(), source: 'local' };
    }
    const hb = this.heartbeats.get(sensor);
    if (!hb) return { service: 'no-heartbeat', log: null, lastHeartbeatAt: null, source: 'agente' };
    const fresh = Date.now() - new Date(hb.receivedAt).getTime() < this.heartbeatTtlMs;
    return {
      service: fresh ? hb.service : 'stale',
      log: hb.log ?? null,
      version: hb.version ?? null,
      telegram: fresh ? (hb.telegram ?? null) : null,
      lastHeartbeatAt: hb.receivedAt,
      source: 'agente',
    };
  }
}
