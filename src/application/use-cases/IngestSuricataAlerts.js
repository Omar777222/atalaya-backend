import { createIdsAlert } from '../../domain/entities/IdsAlert.js';

// El agente del frontend lee eve.json de Suricata y manda las alertas por el peering.
// Se reciben ya validadas por forma; aquí se normalizan y se guardan.
export class IngestSuricataAlerts {
  constructor({ alertStore, toAlert }) {
    Object.assign(this, { alertStore, toAlert });
  }

  async execute({ events }) {
    const alerts = [];
    let rejected = 0;
    for (const e of events) {
      try {
        alerts.push(createIdsAlert(this.toAlert(e)));
      } catch {
        rejected += 1;
      }
    }
    const stored = alerts.length ? await this.alertStore.add(alerts) : [];
    return { accepted: stored.length, rejected, cursor: await this.alertStore.latestCursor() };
  }
}
