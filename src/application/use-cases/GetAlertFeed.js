import { withRule } from './ListIdsAlerts.js';

// Feed para el bot de Telegram. Sin "after" solo devuelve el cursor actual:
// así el bot no reenvía alertas viejas cuando arranca.
export class GetAlertFeed {
  constructor({ alertStore }) {
    this.alertStore = alertStore;
  }

  async execute({ after, limit = 50 }) {
    const cursor = await this.alertStore.latestCursor();
    if (after === undefined) return { cursor, alerts: [] };
    const alerts = (await this.alertStore.list({ after, limit })).reverse(); // en orden cronológico
    return { cursor: alerts.at(-1)?.seq ?? Math.min(after, cursor), alerts: alerts.map(withRule) };
  }
}
