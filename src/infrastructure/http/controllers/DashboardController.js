import { sourceAddressOf } from '../requestContext.js';

export class DashboardController {
  constructor({ getDashboard }) {
    this.getDashboard = getDashboard;
  }

  get = async (req, res, next) => {
    try {
      const data = await this.getDashboard.execute({
        ...req.auth,
        request: {
          secureChannel: req.secure, // true cuando Nginx informa X-Forwarded-Proto: https
          sourceAddress: sourceAddressOf(req),
        },
      });
      res.json(data);
    } catch (err) {
      next(err);
    }
  };
}
