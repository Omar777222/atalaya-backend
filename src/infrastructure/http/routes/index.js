import { Router } from 'express';
import { Roles } from '../../../domain/entities/User.js';
import { authenticate } from '../middlewares/authenticate.js';
import { authorize } from '../middlewares/authorize.js';

export function createApiRouter(c) {
  const router = Router();
  const auth = authenticate(c.authenticateRequest);
  const allow = (...roles) => authorize(c.authorizeAccess, ...roles);

  // Públicas
  router.get('/health', (_req, res) => res.json({ status: 'ok' }));
  router.post('/auth/login', c.authController.login);

  // Requieren token válido
  router.get('/auth/me', auth, c.authController.me);
  router.post('/auth/logout', auth, c.authController.logout);
  router.get('/dashboard', auth, allow(Roles.ADMIN, Roles.ANALYST), c.dashboardController.get);
  router.get('/assets', auth, allow(Roles.ADMIN, Roles.ANALYST), c.assetsController.search);

  // Solo administración
  router.get('/audit', auth, allow(Roles.ADMIN), c.auditController.list);

  return router;
}
