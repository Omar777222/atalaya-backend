// Latido del sensor remoto (Suricata): el agente del frontend confirma cada 30 s que el servicio sigue activo.
export class RecordSensorHeartbeat {
  constructor({ sensorMonitor }) {
    this.sensorMonitor = sensorMonitor;
  }

  async execute({ sensor, service, version, log, telegram }) {
    await this.sensorMonitor.heartbeat(sensor, { service, version, log, telegram });
    return { ok: true };
  }
}
