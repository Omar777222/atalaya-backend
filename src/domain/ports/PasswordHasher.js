export class PasswordHasher {
  // Si hash es null debe devolver false tardando lo mismo (evita descubrir usuarios por tiempo)
  async compare(_plain, _hash) { throw new Error('No implementado'); }
}
