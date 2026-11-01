// Entidad de dominio: describe a un usuario. No conoce Express, JWT ni bases de datos.
export const Roles = Object.freeze({
  ADMIN: 'admin',
  ANALYST: 'analyst',
  CLIENT: 'client', // dueño del sitio protegido: solo ve el resumen de su servicio
});

export class User {
  constructor({ id, username, displayName, role, passwordHash, clientId = null }) {
    this.id = String(id);
    this.username = username;
    this.displayName = displayName;
    this.role = role;
    this.passwordHash = passwordHash;
    this.clientId = clientId === null || clientId === undefined ? null : String(clientId); // empresa a la que pertenece (rol client)
    Object.freeze(this);
  }

  hasAnyRole(roles) {
    return roles.includes(this.role);
  }

  // Lo único que puede salir del sistema: nunca el hash de la contraseña
  toPublic() {
    return { id: this.id, username: this.username, displayName: this.displayName, role: this.role };
  }
}
