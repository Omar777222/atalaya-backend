import { timingSafeEqual, createHash } from 'node:crypto';
import { UnauthorizedError } from '../../../domain/errors/DomainErrors.js';
import { createSecurityEvent, SecurityEventTypes } from '../../../domain/entities/SecurityEvent.js';
import { contextOf } from '../requestContext.js';

const digest = (v) => createHash('sha256').update(String(v)).digest();

// Rutas internas (agente de Suricata y bot de Telegram): exigen la clave compartida
// en el encabezado X-Atalaya-Key. Nginx además bloquea /api/internal desde internet.
export function requireServiceKey(expectedKey, auditLog) {
  const expected = digest(expectedKey);
  return async (req, _res, next) => {
    const provided = req.get('x-atalaya-key');
    if (provided && timingSafeEqual(digest(provided), expected)) return next();
    await auditLog.record(createSecurityEvent({
      type: SecurityEventTypes.SERVICE_KEY_REJECTED, ...contextOf(req),
      detail: provided ? 'Clave de servicio incorrecta' : 'Falta la clave de servicio',
    }));
    next(new UnauthorizedError('Clave de servicio no válida'));
  };
}
