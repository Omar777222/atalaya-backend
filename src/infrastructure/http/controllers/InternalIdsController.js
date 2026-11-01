import { validateFeedQuery, validateHeartbeat, validateSuricataEvents } from '../validators.js';

// Endpoints internos que usa el agente del frontend (clave de servicio, nunca JWT).
export class InternalIdsController {
  constructor({ ingestSuricataAlerts, recordSensorHeartbeat, getAlertFeed, getIdsOverview, getAuditFeed }) {
    Object.assign(this, { ingestSuricataAlerts, recordSensorHeartbeat, getAlertFeed, getIdsOverview, getAuditFeed });
  }

  auditFeed = async (req, res, next) => {
    try { res.json(await this.getAuditFeed.execute(validateFeedQuery(req.query))); } catch (err) { next(err); }
  };

  ingestSuricata = async (req, res, next) => {
    try { res.status(202).json(await this.ingestSuricataAlerts.execute({ events: validateSuricataEvents(req.body) })); } catch (err) { next(err); }
  };

  heartbeat = async (req, res, next) => {
    try { res.json(await this.recordSensorHeartbeat.execute(validateHeartbeat(req.body))); } catch (err) { next(err); }
  };

  feed = async (req, res, next) => {
    try { res.json(await this.getAlertFeed.execute(validateFeedQuery(req.query))); } catch (err) { next(err); }
  };

  // Resumen corto para el comando /estado del bot
  status = async (_req, res, next) => {
    try {
      const o = await this.getIdsOverview.execute();
      res.json({
        totals: o.totals,
        sensors: o.sensors.map(({ id, name, host, status, alertCount, lastAlert }) => ({ id, name, host, status, alertCount, lastAlertAt: lastAlert?.timestamp ?? null })),
        objectives: o.objectives.map(({ id, title, detected }) => ({ id, title, detected })),
      });
    } catch (err) { next(err); }
  };
}
