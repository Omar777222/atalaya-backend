const DAY_MS = 24 * 60 * 60 * 1000;

const isPrivateAddress = (ip = '') =>
  /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1$)/.test(ip);

export class GetDashboard {
  constructor({ auditLog, systemInfo }) {
    Object.assign(this, { auditLog, systemInfo });
  }

  async execute({ user, session, request }) {
    const sourceIsPrivate = isPrivateAddress(request.sourceAddress);

    return {
      user: user.toPublic(),
      session: { issuedAt: session.issuedAt, expiresAt: session.expiresAt, id: session.jti },
      checks: [
        {
          id: 'channel',
          name: 'Canal cifrado',
          passed: request.secureChannel,
          detail: request.secureChannel
            ? 'La petición llegó por HTTPS (ALB y Nginx)'
            : 'Sin HTTPS: estás en el entorno local de desarrollo',
        },
        { id: 'signature', name: 'Firma del token', passed: true, detail: 'HS256 con emisor y audiencia correctos' },
        { id: 'validity', name: 'Token vigente', passed: true, detail: 'No ha expirado y no fue revocado' },
        { id: 'identity', name: 'Usuario activo', passed: true, detail: `${user.username} existe en este momento` },
        { id: 'role', name: 'Rol autorizado', passed: true, detail: `El rol ${user.role} puede ver el resumen` },
        {
          id: 'network',
          name: 'Origen de red privado',
          passed: sourceIsPrivate,
          detail: sourceIsPrivate
            ? `Recibida desde ${request.sourceAddress} (red interna)`
            : `Origen ${request.sourceAddress} fuera de la red privada`,
        },
      ],
      activity: await this.auditLog.summary({ sinceMs: DAY_MS }),
      backend: this.systemInfo.describe(),
    };
  }
}
