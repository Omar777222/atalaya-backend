import { contextOf } from '../requestContext.js';

// Mínimo privilegio: solo pasan los roles indicados en la ruta.
export function authorize(authorizeAccess, ...allowedRoles) {
  return async (req, _res, next) => {
    try {
      await authorizeAccess.execute({ user: req.auth.user, allowedRoles, context: contextOf(req) });
      next();
    } catch (err) {
      next(err);
    }
  };
}
