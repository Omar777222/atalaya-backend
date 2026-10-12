# Atalaya · Backend

API REST en Node.js + Express con **arquitectura hexagonal**, autenticación **JWT**, roles y registro de auditoría.
Proyecto final: Arquitectura Zero Trust en AWS.

## Estructura

```
src/
  domain/          Entidades (User, SecurityEvent), errores y puertos (interfaces)
  application/     Casos de uso: LoginUser, AuthenticateRequest, AuthorizeAccess,
                   LogoutUser, GetSession, GetDashboard, SearchAssets, GetAuditLog
  infrastructure/  Adaptadores: Express (http), JWT y bcrypt (security),
                   memoria (persistence), sistema operativo (system)
  container.js     Conecta cada puerto con su adaptador
```

## Ejecutar en local

```bash
npm install
npm run setup -- "ContraseñaAdmin" "ContraseñaAnalista"
npm run dev
```

## Endpoints

| Método | Ruta | Acceso |
|---|---|---|
| GET | /api/health | Público |
| POST | /api/auth/login | Público |
| GET | /api/auth/me | Token |
| POST | /api/auth/logout | Token (revoca la sesión) |
| GET | /api/dashboard | admin, analyst |
| GET | /api/assets?q= | admin, analyst |
| GET | /api/audit?limit=&type= | admin |

## Controles de seguridad

- JWT HS256 de 15 minutos con emisor, audiencia e identificador único (jti).
- Verificación en cada petición: firma, expiración, revocación y existencia del usuario.
- Roles con mínimo privilegio (403 si el rol no tiene permiso).
- Contraseñas con bcrypt y mensaje de error genérico.
- Validación de entradas (400) y límite de 10 KB por petición.
- Registro de eventos de seguridad en JSON (listo para CloudWatch).
- Encabezados de seguridad con Helmet.
