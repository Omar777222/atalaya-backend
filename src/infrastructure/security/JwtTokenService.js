import { randomUUID } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { TokenService } from '../../domain/ports/TokenService.js';
import { UnauthorizedError } from '../../domain/errors/DomainErrors.js';

const toIso = (seconds) => new Date(seconds * 1000).toISOString();

export class JwtTokenService extends TokenService {
  constructor({ secret, expiresIn, issuer, audience }) {
    super();
    Object.assign(this, { secret, expiresIn, issuer, audience });
  }

  issue({ sub, username, role }) {
    const jti = randomUUID(); // identificador único de la sesión (permite revocarla)
    const token = jwt.sign({ username, role }, this.secret, {
      algorithm: 'HS256',
      subject: String(sub),
      jwtid: jti,
      expiresIn: this.expiresIn,
      issuer: this.issuer,
      audience: this.audience,
    });
    const { iat, exp } = jwt.decode(token);
    return { token, jti, issuedAt: toIso(iat), expiresAt: toIso(exp) };
  }

  verify(token) {
    try {
      const payload = jwt.verify(token, this.secret, {
        algorithms: ['HS256'], // nunca aceptar "none" ni otros algoritmos
        issuer: this.issuer,
        audience: this.audience,
      });
      return { userId: payload.sub, jti: payload.jti, issuedAt: toIso(payload.iat), expiresAt: toIso(payload.exp) };
    } catch {
      throw new UnauthorizedError('Token inválido o expirado');
    }
  }
}
