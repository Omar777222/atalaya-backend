// Raíz de composición: el ÚNICO lugar donde los puertos se conectan con sus adaptadores.
import { config } from './config/env.js';
import { InMemoryUserRepository } from './infrastructure/persistence/InMemoryUserRepository.js';
import { InMemoryRevokedTokenStore } from './infrastructure/persistence/InMemoryRevokedTokenStore.js';
import { InMemoryAuditLog } from './infrastructure/persistence/InMemoryAuditLog.js';
import { StaticAssetCatalog } from './infrastructure/persistence/StaticAssetCatalog.js';
import { BcryptPasswordHasher } from './infrastructure/security/BcryptPasswordHasher.js';
import { JwtTokenService } from './infrastructure/security/JwtTokenService.js';
import { OsSystemInfo } from './infrastructure/system/OsSystemInfo.js';
import { LoginUser } from './application/use-cases/LoginUser.js';
import { AuthenticateRequest } from './application/use-cases/AuthenticateRequest.js';
import { AuthorizeAccess } from './application/use-cases/AuthorizeAccess.js';
import { LogoutUser } from './application/use-cases/LogoutUser.js';
import { GetSession } from './application/use-cases/GetSession.js';
import { GetDashboard } from './application/use-cases/GetDashboard.js';
import { SearchAssets } from './application/use-cases/SearchAssets.js';
import { GetAuditLog } from './application/use-cases/GetAuditLog.js';
import { AuthController } from './infrastructure/http/controllers/AuthController.js';
import { DashboardController } from './infrastructure/http/controllers/DashboardController.js';
import { AssetsController } from './infrastructure/http/controllers/AssetsController.js';
import { AuditController } from './infrastructure/http/controllers/AuditController.js';

export function buildContainer() {
  // Adaptadores (infraestructura)
  const userRepository = new InMemoryUserRepository(config.users);
  const revokedTokenStore = new InMemoryRevokedTokenStore();
  const auditLog = new InMemoryAuditLog();
  const assetCatalog = new StaticAssetCatalog();
  const passwordHasher = new BcryptPasswordHasher();
  const tokenService = new JwtTokenService(config.jwt);
  const systemInfo = new OsSystemInfo();

  // Casos de uso (aplicación)
  const loginUser = new LoginUser({ userRepository, passwordHasher, tokenService, auditLog });
  const authenticateRequest = new AuthenticateRequest({ tokenService, revokedTokenStore, userRepository, auditLog });
  const authorizeAccess = new AuthorizeAccess({ auditLog });
  const logoutUser = new LogoutUser({ revokedTokenStore, auditLog });
  const getSession = new GetSession();
  const getDashboard = new GetDashboard({ auditLog, systemInfo });
  const searchAssets = new SearchAssets({ assetCatalog });
  const getAuditLog = new GetAuditLog({ auditLog });

  return {
    config,
    auditLog,
    authenticateRequest,
    authorizeAccess,
    authController: new AuthController({ loginUser, logoutUser, getSession }),
    dashboardController: new DashboardController({ getDashboard }),
    assetsController: new AssetsController({ searchAssets }),
    auditController: new AuditController({ getAuditLog }),
  };
}
