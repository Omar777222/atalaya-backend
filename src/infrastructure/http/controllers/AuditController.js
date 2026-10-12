import { validateAuditFilters } from '../validators.js';

export class AuditController {
  constructor({ getAuditLog }) {
    this.getAuditLog = getAuditLog;
  }

  list = async (req, res, next) => {
    try {
      const filters = validateAuditFilters(req.query);
      res.json(await this.getAuditLog.execute(filters));
    } catch (err) {
      next(err);
    }
  };
}
