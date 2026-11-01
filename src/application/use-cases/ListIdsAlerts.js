import { findRule } from '../../domain/catalog/detectionCatalog.js';

// Agrega a cada alerta la explicación de la regla que la generó (análisis que pide la práctica).
export const withRule = (a) => {
  const r = findRule(a.sensor, a.sid);
  return r ? { ...a, rule: { file: r.file, text: r.text, trigger: r.trigger, reason: r.reason } } : { ...a, rule: null };
};

// Lista de alertas con filtros. "after" permite pedir solo las nuevas (sondeo cada pocos segundos).
export class ListIdsAlerts {
  constructor({ alertStore }) {
    this.alertStore = alertStore;
  }

  async execute({ sensor, objective, after = 0, limit = 100 }) {
    const alerts = await this.alertStore.list({ sensor, objective, after: after ?? 0, limit });
    return { cursor: await this.alertStore.latestCursor(), total: alerts.length, alerts: alerts.map(withRule) };
  }
}
