import { contextOf } from '../requestContext.js';
import { validateAlertFilters } from '../validators.js';

// Endpoints que usa el sitio (requieren JWT).
export class IdsController {
  constructor({ getIdsOverview, listIdsAlerts, getIdsSetup, resetIdsAlerts }) {
    Object.assign(this, { getIdsOverview, listIdsAlerts, getIdsSetup, resetIdsAlerts });
  }

  overview = async (_req, res, next) => {
    try { res.json(await this.getIdsOverview.execute()); } catch (err) { next(err); }
  };

  alerts = async (req, res, next) => {
    try { res.json(await this.listIdsAlerts.execute(validateAlertFilters(req.query))); } catch (err) { next(err); }
  };

  setup = async (_req, res, next) => {
    try { res.json(await this.getIdsSetup.execute()); } catch (err) { next(err); }
  };

  reset = async (req, res, next) => {
    try {
      res.json(await this.resetIdsAlerts.execute({ user: req.auth.user, context: contextOf(req) }));
    } catch (err) { next(err); }
  };
}
