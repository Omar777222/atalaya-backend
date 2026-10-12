import { bearerTokenOf, contextOf } from '../requestContext.js';

// Verifica el JWT en CADA petición: nunca confiar, siempre verificar.
export function authenticate(authenticateRequest) {
  return async (req, _res, next) => {
    try {
      const { user, session } = await authenticateRequest.execute({
        token: bearerTokenOf(req),
        context: contextOf(req),
      });
      req.auth = { user, session };
      next();
    } catch (err) {
      next(err);
    }
  };
}
