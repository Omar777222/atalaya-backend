export class GetSession {
  execute({ user, session }) {
    return { user: user.toPublic(), session: { issuedAt: session.issuedAt, expiresAt: session.expiresAt } };
  }
}
