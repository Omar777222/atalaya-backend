import { CLIENT_CATEGORIES } from '../../domain/catalog/clientCatalog.js';
import { Sensors } from '../../domain/catalog/detectionCatalog.js';

const DAY = 24 * 60 * 60 * 1000;
const BAD = new Set(['inactive', 'failed', 'stale']);
const startOfDay = (t) => { const d = new Date(t); d.setHours(0, 0, 0, 0); return d.getTime(); };

// Portal del cliente: estado de protección de SU sitio en lenguaje sencillo.
// No expone IPs internas, reglas ni configuración de los sensores.
export class GetClientSummary {
  constructor({ alertStore, sensorMonitor, service, clientRepository = null }) {
    Object.assign(this, { alertStore, sensorMonitor, service, clientRepository });
  }

  // Con base de datos, los datos del servicio salen de la empresa del usuario (tabla clients)
  async serviceFor(user) {
    const client = user?.clientId && this.clientRepository ? await this.clientRepository.findById(user.clientId) : null;
    if (!client) return this.service;
    return { ...this.service, clientName: client.name, site: client.site, plan: client.plan, contact: client.contact ?? this.service.contact };
  }

  async execute({ user } = {}) {
    const now = Date.now();
    const alerts = await this.alertStore.all();
    const sensors = await Promise.all([Sensors.SURICATA, Sensors.SNORT].map(async (id) => {
      const status = await this.sensorMonitor.status(id);
      return {
        id,
        name: id === Sensors.SURICATA ? 'Vigilancia de la red (Suricata)' : 'Vigilancia del servidor (Snort)',
        state: status.service === 'active' ? 'activo' : BAD.has(status.service) ? 'falla' : 'sin-datos',
      };
    }));

    const today = startOfDay(now);
    const days = Array.from({ length: 7 }, (_, i) => ({ day: new Date(today - (6 - i) * DAY).toISOString(), count: 0 }));
    const categories = new Map();
    const sources = new Set();
    let todayCount = 0;
    let highLastHour = 0;

    for (const a of alerts) {
      const t = new Date(a.timestamp).getTime();
      if (t < today - 6 * DAY) continue;
      days[Math.min(6, Math.floor((startOfDay(t) - (today - 6 * DAY)) / DAY))].count += 1;
      if (t >= today) todayCount += 1;
      if (now - t < 60 * 60 * 1000 && a.priority === 1) highLastHour += 1;
      if (a.srcIp) sources.add(a.srcIp);
      const key = a.objective ?? 'other';
      const c = categories.get(key) ?? { id: key, ...CLIENT_CATEGORIES[key], count: 0, lastAt: null, high: false };
      c.count += 1;
      if (!c.lastAt || t > new Date(c.lastAt).getTime()) c.lastAt = a.timestamp;
      if (a.priority === 1) c.high = true;
      categories.set(key, c);
    }

    const up = sensors.filter((s) => s.state === 'activo').length;
    let status = 'sin-datos';
    if (sensors.some((s) => s.state === 'falla')) status = 'degradado';
    else if (highLastHour > 0) status = 'atencion';
    else if (up === sensors.length) status = 'protegido';

    return {
      service: await this.serviceFor(user),
      generatedAt: new Date(now).toISOString(),
      status,
      sensors,
      stats: { today: todayCount, week: days.reduce((n, d) => n + d.count, 0), sources: sources.size, highLastHour },
      days,
      incidents: [...categories.values()].sort((a, b) => new Date(b.lastAt) - new Date(a.lastAt)),
    };
  }
}
