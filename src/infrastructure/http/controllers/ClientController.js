// Portal del cliente del servicio (rol client; admin también lo puede revisar).
export class ClientController {
  constructor({ getClientSummary }) {
    this.getClientSummary = getClientSummary;
  }

  summary = async (req, res, next) => {
    try { res.json(await this.getClientSummary.execute({ user: req.auth.user })); } catch (err) { next(err); }
  };
}
