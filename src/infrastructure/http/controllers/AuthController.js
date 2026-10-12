import { contextOf } from '../requestContext.js';
import { validateCredentials } from '../validators.js';

export class AuthController {
  constructor({ loginUser, logoutUser, getSession }) {
    Object.assign(this, { loginUser, logoutUser, getSession });
  }

  login = async (req, res, next) => {
    try {
      const credentials = validateCredentials(req.body);
      const result = await this.loginUser.execute({ ...credentials, context: contextOf(req) });
      res.json(result);
    } catch (err) {
      next(err);
    }
  };

  logout = async (req, res, next) => {
    try {
      await this.logoutUser.execute({ ...req.auth, context: contextOf(req) });
      res.status(204).end();
    } catch (err) {
      next(err);
    }
  };

  me = (req, res) => {
    res.json(this.getSession.execute(req.auth));
  };
}
