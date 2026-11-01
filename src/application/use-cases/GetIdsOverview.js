import { OBJECTIVES, Sensors, findRule } from '../../domain/catalog/detectionCatalog.js';

const MINUTE = 60 * 1000;
const TIMELINE_MINUTES = 30;
const SENSOR_LIST = [Sensors.SURICATA, Sensors.SNORT];

const top = (map, n) => [...map.values()].sort((a, b) => b.count - a.count).slice(0, n);

// Resumen del centro de monitoreo: totales, estado de los sensores,
// avance de las pruebas de la práctica y línea de tiempo de los últimos 30 minutos.
export class GetIdsOverview {
  constructor({ alertStore, sensorMonitor, sensorsConfig }) {
    Object.assign(this, { alertStore, sensorMonitor, sensorsConfig });
  }

  async execute() {
    const now = Date.now();
    const alerts = await this.alertStore.all();

    const perSensor = Object.fromEntries(SENSOR_LIST.map((s) => [s, { count: 0, last: null }]));
    const perObjective = Object.fromEntries(OBJECTIVES.map((o) => [o.id, {
      [Sensors.SURICATA]: { count: 0, lastAt: null },
      [Sensors.SNORT]: { count: 0, lastAt: null },
    }]));
    const signatures = new Map();
    const sources = new Map();
    const bucketStart = Math.floor(now / MINUTE) * MINUTE - (TIMELINE_MINUTES - 1) * MINUTE;
    const timeline = Array.from({ length: TIMELINE_MINUTES }, (_, i) => ({
      minute: new Date(bucketStart + i * MINUTE).toISOString(), suricata: 0, snort: 0,
    }));
    let lastHour = 0;

    for (const a of alerts) {
      const t = new Date(a.timestamp).getTime();
      const s = perSensor[a.sensor];
      s.count += 1;
      if (!s.last || t >= new Date(s.last.timestamp).getTime()) s.last = a;
      if (now - t <= 60 * MINUTE) lastHour += 1;

      if (a.objective) {
        const o = perObjective[a.objective][a.sensor];
        o.count += 1;
        if (!o.lastAt || t > new Date(o.lastAt).getTime()) o.lastAt = a.timestamp;
      }

      const sigKey = `${a.sensor}:${a.sid}`;
      const sig = signatures.get(sigKey) ?? { sensor: a.sensor, sid: a.sid, message: a.message, objective: a.objective, count: 0 };
      sig.count += 1;
      signatures.set(sigKey, sig);

      if (a.srcIp) {
        const src = sources.get(a.srcIp) ?? { ip: a.srcIp, count: 0 };
        src.count += 1;
        sources.set(a.srcIp, src);
      }

      const idx = Math.floor((t - bucketStart) / MINUTE);
      if (idx >= 0 && idx < TIMELINE_MINUTES) timeline[idx][a.sensor] += 1;
    }

    const sensors = await Promise.all(SENSOR_LIST.map(async (id) => ({
      ...this.sensorsConfig[id],
      id,
      status: await this.sensorMonitor.status(id),
      alertCount: perSensor[id].count,
      lastAlert: perSensor[id].last,
    })));

    return {
      generatedAt: new Date(now).toISOString(),
      cursor: await this.alertStore.latestCursor(),
      totals: {
        all: alerts.length,
        lastHour,
        suricata: perSensor.suricata.count,
        snort: perSensor.snort.count,
      },
      lastAlert: [perSensor.suricata.last, perSensor.snort.last].filter(Boolean)
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0] ?? null,
      sensors,
      objectives: OBJECTIVES.map((o) => {
        const detections = perObjective[o.id];
        const detected = detections.suricata.count + detections.snort.count > 0;
        return { ...o, detected, detections };
      }),
      timeline,
      topSignatures: top(signatures, 6).map((s) => ({ ...s, local: Boolean(findRule(s.sensor, s.sid)) })),
      topSources: top(sources, 5),
      latest: await this.alertStore.list({ limit: 8 }),
    };
  }
}
