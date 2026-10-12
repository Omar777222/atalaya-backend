import { UserRepository } from '../../domain/ports/UserRepository.js';
import { User } from '../../domain/entities/User.js';

// Adaptador de persistencia en memoria. Para usar una base de datos real,
// solo se crea otro adaptador (por ejemplo MySqlUserRepository) y se cambia en container.js.
export class InMemoryUserRepository extends UserRepository {
  constructor(seedUsers = []) {
    super();
    this.users = new Map(seedUsers.map((u) => [String(u.id), new User(u)]));
  }

  async findByUsername(username) {
    return [...this.users.values()].find((u) => u.username === username) ?? null;
  }

  async findById(id) {
    return this.users.get(String(id)) ?? null;
  }
}
