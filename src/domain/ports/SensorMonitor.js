// Puerto: estado de cada sensor (servicio activo, archivo de alertas, último latido).
export class SensorMonitor {
  async status(_sensor) { throw new Error('No implementado'); }
  async heartbeat(_sensor, _info) { throw new Error('No implementado'); }
}
