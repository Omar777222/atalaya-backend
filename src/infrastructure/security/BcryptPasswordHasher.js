import bcrypt from 'bcryptjs';
import { PasswordHasher } from '../../domain/ports/PasswordHasher.js';

export class BcryptPasswordHasher extends PasswordHasher {
  constructor() {
    super();
    this.dummyHash = bcrypt.hashSync('hash-de-relleno-para-igualar-tiempos', 12);
  }

  async compare(plain, hash) {
    const result = await bcrypt.compare(plain, hash ?? this.dummyHash);
    return hash ? result : false;
  }
}
