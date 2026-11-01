import { Router } from 'express';
import { Roles } from '../../../domain/entities/User.js';
import { authenticate } from '../middlewares/authenticate.js';
import { authorize } from '../middlewares/authorize.js';
import { requireServiceKey } from '../middlewares/serviceKey.js';

// Rutas del sitio: JWT en cada petición + rol.
export function createApiRouter(c) {
  const router = Router();
  const auth = authenticate(c.authenticateRequest);
  const allow = (...roles) => authorize(c.authorizeAccess, ...roles);
  const staff = allow(Roles.ADMIN, Roles.ANALYST);

  // Públicas
  router.get('/health', (_req, res) => res.json({ status: 'ok' }));
  router.post('/auth/login', c.authController.login);

  // Sesión
  router.get('/auth/me', auth, c.authController.me);
  router.post('/auth/logout', auth, c.authController.logout);

  // Centro de monitoreo IDS
  router.get('/ids/overview', auth, staff, c.idsController.overview);
  router.get('/ids/alerts', auth, staff, c.idsController.alerts);
  router.get('/ids/setup', auth, staff, c.idsController.setup);
  router.post('/ids/reset', auth, allow(Roles.ADMIN), c.idsController.reset);

  // Portal del cliente del servicio
  router.get('/client/summary', auth, allow(Roles.CLIENT, Roles.ADMIN), c.clientController.summary);

  // Solo administración
  router.get('/audit', auth, allow(Roles.ADMIN), c.auditController.list);

  return router;
}

// Rutas internas: solo el agente del frontend (clave de servicio). Nginx las bloquea desde internet.
export function createInternalRouter(c) {
  const router = Router();
  router.use(requireServiceKey(c.config.ids.ingestKey, c.auditLog));
  router.post('/ids/suricata', c.internalIdsController.ingestSuricata);
  router.post('/ids/heartbeat', c.internalIdsController.heartbeat);
  router.get('/ids/feed', c.internalIdsController.feed);
  router.get('/ids/status', c.internalIdsController.status);
  router.get('/audit/feed', c.internalIdsController.auditFeed); // accesos al sitio para Telegram
  return router;
}
