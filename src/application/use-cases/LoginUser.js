import { InvalidCredentialsError } from '../../domain/errors/DomainErrors.js';
import { createSecurityEvent, SecurityEventTypes } from '../../domain/entities/SecurityEvent.js';

export class LoginUser {
  constructor({ userRepository, passwordHasher, tokenService, auditLog }) {
    Object.assign(this, { userRepository, passwordHasher, tokenService, auditLog });
  }

  async execute({ username, password, context }) {
    const user = await this.userRepository.findByUsername(username);
    // Se compara aunque el usuario no exista, para no revelar qué usuarios existen
    const valid = await this.passwordHasher.compare(password, user?.passwordHash ?? null);

    if (!user || !valid) {
      await this.auditLog.record(createSecurityEvent({
        type: SecurityEventTypes.LOGIN_FAILURE, username, ...context, detail: 'Credenciales incorrectas',
      }));
      throw new InvalidCredentialsError();
    }

    const session = this.tokenService.issue({ sub: user.id, username: user.username, role: user.role });
    await this.auditLog.record(createSecurityEvent({
      type: SecurityEventTypes.LOGIN_SUCCESS, username: user.username, ...context, detail: `Rol ${user.role}`,
    }));

    return { token: session.token, expiresAt: session.expiresAt, user: user.toPublic() };
  }
}
