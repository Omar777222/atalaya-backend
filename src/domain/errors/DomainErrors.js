export class DomainError extends Error {
  constructor(message, code) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
  }
}

export class ValidationError extends DomainError {
  constructor(message) { super(message, 'VALIDATION_ERROR'); }
}

export class InvalidCredentialsError extends DomainError {
  constructor() { super('Usuario o contraseña incorrectos', 'INVALID_CREDENTIALS'); }
}

export class UnauthorizedError extends DomainError {
  constructor(message = 'Tu sesión no es válida. Inicia sesión de nuevo.') { super(message, 'UNAUTHORIZED'); }
}

export class ForbiddenError extends DomainError {
  constructor(message = 'Tu rol no tiene permiso para este recurso') { super(message, 'FORBIDDEN'); }
}
