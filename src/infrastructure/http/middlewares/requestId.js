import { randomUUID } from 'node:crypto';

// Cada petición recibe un identificador para rastrearla en los registros.
export function requestId(req, res, next) {
  req.requestId = randomUUID();
  res.set('X-Request-Id', req.requestId);
  next();
}
