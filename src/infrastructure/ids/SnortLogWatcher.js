import { FileTailer } from './FileTailer.js';
import { parseFastLine } from './alertParsers.js';
import { createIdsAlert } from '../../domain/entities/IdsAlert.js';
import { Sensors } from '../../domain/catalog/detectionCatalog.js';

const STATUS_BY_ERROR = { ENOENT: 'missing', EACCES: 'forbidden', EPERM: 'forbidden' };

// Adaptador: lee /var/log/snort/alert_fast.txt en el mismo servidor del backend
// y guarda cada línea como una alerta normalizada.
export class SnortLogWatcher {
  constructor({ path, alertStore, intervalMs = 1000 }) {
    this.path = path;
    this.alertStore = alertStore;
    this.state = { status: 'starting', error: null, lastReadAt: null };
    this.tailer = new FileTailer({
      path,
      intervalMs,
      onLines: (lines) => this.ingest(lines),
      onState: (s) => {
        this.state = s.ok
          ? { status: 'ok', error: null, lastReadAt: new Date().toISOString() }
          : { status: STATUS_BY_ERROR[s.error] ?? 'error', error: s.error, lastReadAt: this.state.lastReadAt };
      },
    });
  }

  async ingest(lines) {
    const alerts = [];
    for (const line of lines) {
      const parsed = parseFastLine(line, { sensor: Sensors.SNORT });
      if (!parsed) continue;
      try {
        alerts.push(createIdsAlert(parsed));
      } catch { /* línea corrupta: se ignora */ }
    }
    if (alerts.length) await this.alertStore.add(alerts);
  }

  // Lo que se muestra en la tarjeta del sensor (sirve para diagnosticar permisos o rutas)
  describe() {
    return { path: this.path, ...this.state };
  }

  start() {
    this.tailer.start();
  }
}
