// Evento de seguridad: cada acción relevante queda registrada para auditoría.
export const SecurityEventTypes = Object.freeze({
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  LOGOUT: 'LOGOUT',
  TOKEN_REJECTED: 'TOKEN_REJECTED',
  ACCESS_DENIED: 'ACCESS_DENIED',
  INPUT_REJECTED: 'INPUT_REJECTED',
});

const SEVERITY = {
  LOGIN_SUCCESS: 'info',
  LOGOUT: 'info',
  LOGIN_FAILURE: 'warning',
  INPUT_REJECTED: 'warning',
  TOKEN_REJECTED: 'high',
  ACCESS_DENIED: 'high',
};

export function createSecurityEvent({ type, username = null, ip = null, path = null, detail = '', requestId = null }) {
  if (!SecurityEventTypes[type]) throw new Error(`Tipo de evento desconocido: ${type}`);
  return Object.freeze({
    id: globalThis.crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    type,
    severity: SEVERITY[type],
    username,
    ip,
    path,
    detail,
    requestId,
  });
}
