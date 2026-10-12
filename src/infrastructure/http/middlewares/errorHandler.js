import { DomainError, ValidationError } from '../../../domain/errors/DomainErrors.js';
import { createSecurityEvent, SecurityEventTypes } from '../../../domain/entities/SecurityEvent.js';
import { contextOf } from '../requestContext.js';

const STATUS_BY_CODE = {
  VALIDATION_ERROR: 400,
  INVALID_CREDENTIALS: 401,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
};

export function errorHandler(auditLog) {
  // eslint-disable-next-line no-unused-vars
  return async (err, req, res, _next) => {
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'El cuerpo de la petición no es JSON válido' });
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'La petición es demasiado grande' });

    if (err instanceof ValidationError) {
      await auditLog.record(createSecurityEvent({
        type: SecurityEventTypes.INPUT_REJECTED,
        username: req.auth?.user.username ?? null,
        ...contextOf(req),
        detail: err.message,
      }));
    }

    if (err instanceof DomainError) {
      return res.status(STATUS_BY_CODE[err.code] ?? 400).json({ error: err.message, requestId: req.requestId });
    }

    console.error(JSON.stringify({ source: 'atalaya-api', level: 'error', requestId: req.requestId, message: err.message }));
    res.status(500).json({ error: 'Error interno del servidor', requestId: req.requestId });
  };
}
