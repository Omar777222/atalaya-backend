import bcrypt from 'bcryptjs';

const password = process.argv[2];
if (!password || password.length < 10) {
  console.error('Uso: npm run hash -- "TuContraseña"   (mínimo 10 caracteres)');
  process.exit(1);
}
console.log(bcrypt.hashSync(password, 12));
