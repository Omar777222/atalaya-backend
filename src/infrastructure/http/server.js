import express from 'express';
import helmet from 'helmet';
import { requestId } from './middlewares/requestId.js';
import { errorHandler } from './middlewares/errorHandler.js';
import { createApiRouter, createInternalRouter } from './routes/index.js';

export function createServer(container) {
  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', container.config.trustProxy); // IP real enviada por Nginx
  app.use(helmet());
  app.use(requestId);
  app.use((_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

  // Internas primero: aceptan lotes de alertas (hasta 256 KB). El resto de la API sigue en 10 KB.
  app.use('/api/internal', express.json({ limit: '256kb' }), createInternalRouter(container));
  app.use(express.json({ limit: '10kb' }));
  app.use('/api', createApiRouter(container));

  app.use((req, res) => res.status(404).json({ error: 'Recurso no encontrado', requestId: req.requestId }));
  app.use(errorHandler(container.auditLog));
  return app;
}
