// Raíz de composición: el ÚNICO lugar donde los puertos se conectan con sus adaptadores.
import { config } from './config/env.js';
import { InMemoryUserRepository } from './infrastructure/persistence/InMemoryUserRepository.js';
import { InMemoryRevokedTokenStore } from './infrastructure/persistence/InMemoryRevokedTokenStore.js';
import { InMemoryAuditLog } from './infrastructure/persistence/InMemoryAuditLog.js';
import { BcryptPasswordHasher } from './infrastructure/security/BcryptPasswordHasher.js';
import { JwtTokenService } from './infrastructure/security/JwtTokenService.js';
import { InMemoryIdsAlertStore } from './infrastructure/ids/InMemoryIdsAlertStore.js';
import { LocalAndRemoteSensorMonitor } from './infrastructure/ids/LocalAndRemoteSensorMonitor.js';
import { SnortLogWatcher } from './infrastructure/ids/SnortLogWatcher.js';
import { fromEveAlert } from './infrastructure/ids/alertParsers.js';
import { LoginUser } from './application/use-cases/LoginUser.js';
import { AuthenticateRequest } from './application/use-cases/AuthenticateRequest.js';
import { AuthorizeAccess } from './application/use-cases/AuthorizeAccess.js';
import { LogoutUser } from './application/use-cases/LogoutUser.js';
import { GetSession } from './application/use-cases/GetSession.js';
import { GetAuditLog } from './application/use-cases/GetAuditLog.js';
import { GetIdsOverview } from './application/use-cases/GetIdsOverview.js';
import { ListIdsAlerts } from './application/use-cases/ListIdsAlerts.js';
import { GetIdsSetup } from './application/use-cases/GetIdsSetup.js';
import { IngestSuricataAlerts } from './application/use-cases/IngestSuricataAlerts.js';
import { RecordSensorHeartbeat } from './application/use-cases/RecordSensorHeartbeat.js';
import { ResetIdsAlerts } from './application/use-cases/ResetIdsAlerts.js';
import { GetAlertFeed } from './application/use-cases/GetAlertFeed.js';
import { GetAuditFeed } from './application/use-cases/GetAuditFeed.js';
import { GetClientSummary } from './application/use-cases/GetClientSummary.js';
import { ClientController } from './infrastructure/http/controllers/ClientController.js';
import { AuthController } from './infrastructure/http/controllers/AuthController.js';
import { AuditController } from './infrastructure/http/controllers/AuditController.js';
import { IdsController } from './infrastructure/http/controllers/IdsController.js';
import { InternalIdsController } from './infrastructure/http/controllers/InternalIdsController.js';

// Persistencia: PostgreSQL si hay DATABASE_URL; si no, memoria (desarrollo local).
// Los casos de uso no cambian: solo se elige otro adaptador para cada puerto (arquitectura hexagonal).
async function buildPersistence() {
  if (!config.db.url) {
    const auditLog = new InMemoryAuditLog();
    const alertStore = new InMemoryIdsAlertStore();
    return {
      userRepository: new InMemoryUserRepository(config.users),
      revokedTokenStore: new InMemoryRevokedTokenStore(),
      auditLog,
      alertStore,
      clientRepository: null,
      storage: {
        engine: 'Memoria', persistent: false,
        stats: async () => ({ alerts: (await alertStore.all()).length, auditEvents: auditLog.events.length, since: null }),
      },
    };
  }

  const pg = await import('./infrastructure/persistence/postgres/database.js');
  const { PostgresUserRepository, PostgresClientRepository } = await import('./infrastructure/persistence/postgres/PostgresUserRepository.js');
  const { PostgresAuditLog } = await import('./infrastructure/persistence/postgres/PostgresAuditLog.js');
  const { PostgresRevokedTokenStore } = await import('./infrastructure/persistence/postgres/PostgresRevokedTokenStore.js');
  const { PostgresIdsAlertStore } = await import('./infrastructure/persistence/postgres/PostgresIdsAlertStore.js');

  const pool = await pg.openDatabase({ url: config.db.url, max: config.db.poolMax });
  await pg.migrate(pool);
  const { rows } = await pool.query('SHOW server_version');

  const clientRepository = new PostgresClientRepository(pool);
  const userRepository = new PostgresUserRepository(pool);
  const clientId = await clientRepository.seed({
    name: config.service.clientName, site: config.service.site, plan: config.service.plan, contact: config.service.contact,
  });
  await userRepository.seed(config.users, clientId); // los usuarios del .env se sincronizan en cada arranque

  const auditLog = new PostgresAuditLog(pool);
  const alertStore = new PostgresIdsAlertStore(pool);
  await alertStore.init();
  return {
    userRepository,
    revokedTokenStore: new PostgresRevokedTokenStore(pool),
    auditLog,
    alertStore,
    clientRepository,
    pool,
    storage: {
      engine: `PostgreSQL ${rows[0].server_version.split(' ')[0]}`, persistent: true,
      stats: async () => {
        const a = await alertStore.count();
        return { alerts: a.total, since: a.since, auditEvents: await auditLog.count() };
      },
    },
  };
}

export async function buildContainer() {
  const { userRepository, revokedTokenStore, auditLog, alertStore, clientRepository, storage, pool } = await buildPersistence();
  // Adaptadores (infraestructura)
  const passwordHasher = new BcryptPasswordHasher();
  const tokenService = new JwtTokenService(config.jwt);
  const snortWatcher = new SnortLogWatcher({ path: config.ids.snort.alertFile, alertStore });
  const sensorMonitor = new LocalAndRemoteSensorMonitor({ snortUnit: config.ids.snort.service, snortWatcher });

  // Casos de uso (aplicación)
  const loginUser = new LoginUser({ userRepository, passwordHasher, tokenService, auditLog });
  const authenticateRequest = new AuthenticateRequest({ tokenService, revokedTokenStore, userRepository, auditLog });
  const authorizeAccess = new AuthorizeAccess({ auditLog });
  const logoutUser = new LogoutUser({ revokedTokenStore, auditLog });
  const getSession = new GetSession();
  const getAuditLog = new GetAuditLog({ auditLog });
  const sensorsConfig = config.ids.sensors;
  const getIdsOverview = new GetIdsOverview({ alertStore, sensorMonitor, sensorsConfig });
  const listIdsAlerts = new ListIdsAlerts({ alertStore });
  const getIdsSetup = new GetIdsSetup({ sensorsConfig, targets: config.ids.targets, storage });
  const ingestSuricataAlerts = new IngestSuricataAlerts({ alertStore, toAlert: fromEveAlert });
  const recordSensorHeartbeat = new RecordSensorHeartbeat({ sensorMonitor });
  const resetIdsAlerts = new ResetIdsAlerts({ alertStore, auditLog });
  const getAlertFeed = new GetAlertFeed({ alertStore });
  const getAuditFeed = new GetAuditFeed({ auditLog });
  const getClientSummary = new GetClientSummary({ alertStore, sensorMonitor, service: config.service, clientRepository });

  return {
    config,
    pool,
    storage,
    auditLog,
    snortWatcher,
    authenticateRequest,
    authorizeAccess,
    authController: new AuthController({ loginUser, logoutUser, getSession }),
    auditController: new AuditController({ getAuditLog }),
    idsController: new IdsController({ getIdsOverview, listIdsAlerts, getIdsSetup, resetIdsAlerts }),
    internalIdsController: new InternalIdsController({ ingestSuricataAlerts, recordSensorHeartbeat, getAlertFeed, getIdsOverview, getAuditFeed }),
    clientController: new ClientController({ getClientSummary }),
  };
}
