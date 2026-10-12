export class TokenService {
  // Devuelve { token, jti, issuedAt, expiresAt }
  issue(_claims) { throw new Error('No implementado'); }
  // Devuelve { userId, jti, issuedAt, expiresAt } o lanza UnauthorizedError
  verify(_token) { throw new Error('No implementado'); }
}
