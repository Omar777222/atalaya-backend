import { ValidationError } from '../../domain/errors/DomainErrors.js';
import { SecurityEventTypes } from '../../domain/entities/SecurityEvent.js';

const USERNAME_RE = /^[a-zA-Z0-9._-]{3,30}$/;
// Búsqueda: solo letras, números, espacios y . - _ / (máximo 40 caracteres)
const SEARCH_RE = /^[\p{L}\p{N} ._\-/]{0,40}$/u;

export function validateCredentials(body) {
  const { username, password } = body ?? {};
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) {
    throw new ValidationError('El usuario solo admite letras, números y . _ - (3 a 30 caracteres)');
  }
  if (typeof password !== 'string' || password.length < 1 || password.length > 128) {
    throw new ValidationError('La contraseña tiene un formato inválido');
  }
  return { username, password };
}

export function validateSearch(query) {
  const q = typeof query.q === 'string' ? query.q : '';
  if (!SEARCH_RE.test(q)) {
    throw new ValidationError('La búsqueda solo admite letras, números, espacios y . _ - / (máximo 40)');
  }
  return q;
}

export function validateAuditFilters(query) {
  const limit = query.limit === undefined ? 50 : Number(query.limit);
  if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
    throw new ValidationError('El límite debe ser un número entre 1 y 200');
  }
  const type = query.type || undefined;
  if (type && !SecurityEventTypes[type]) {
    throw new ValidationError('Tipo de evento no válido');
  }
  return { limit, type };
}
