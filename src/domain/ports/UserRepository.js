// PUERTO: el dominio declara QUÉ necesita; un adaptador decide CÓMO (memoria, MySQL, DynamoDB...).
export class UserRepository {
  async findByUsername(_username) { throw new Error('No implementado'); }
  async findById(_id) { throw new Error('No implementado'); }
}
