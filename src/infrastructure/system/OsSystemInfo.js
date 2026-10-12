import os from 'node:os';
import { SystemInfo } from '../../domain/ports/SystemInfo.js';

// La IP privada del backend sirve como evidencia de que respondió la VPC Backend.
export class OsSystemInfo extends SystemInfo {
  describe() {
    const privateIps = Object.values(os.networkInterfaces())
      .flat()
      .filter((i) => i && i.family === 'IPv4' && !i.internal)
      .map((i) => i.address);
    return {
      hostname: os.hostname(),
      privateIps,
      uptimeMinutes: Math.round(process.uptime() / 60),
      serverTime: new Date().toISOString(),
    };
  }
}
