import { buildContainer } from './container.js';
import { createServer } from './infrastructure/http/server.js';

let container;
try {
  container = await buildContainer();
} catch (err) {
  console.error(`No se pudo iniciar la API: ${err.message}`);
  console.error('Revisa DATABASE_URL en el .env y que PostgreSQL esté activo (systemctl status postgresql).');
  process.exit(1);
}
const app = createServer(container);
const { host, port, ids } = container.config;

container.snortWatcher.start();

app.listen(port, host, () => {
  console.log(`Atalaya API escuchando en http://${host}:${port}`);
  console.log(`Leyendo alertas de Snort en ${ids.snort.alertFile}`);
  console.log(`Almacenamiento: ${container.storage.engine}`);
});
