import { Sensors, findRule } from '../catalog/detectionCatalog.js';

// Alerta de un IDS (Snort o Suricata) ya normalizada al mismo formato.
// No sabe de archivos ni de HTTP: solo describe qué se detectó.
const SENSOR_VALUES = new Set(Object.values(Sensors));

export function createIdsAlert({
  sensor, timestamp, gid = 1, sid, rev = 1, message, classification = null, priority = null,
  protocol = null, srcIp = null, srcPort = null, dstIp = null, dstPort = null, raw = null, extra = null,
}) {
  if (!SENSOR_VALUES.has(sensor)) throw new Error(`Sensor desconocido: ${sensor}`);
  if (!Number.isInteger(sid)) throw new Error('El SID debe ser un entero');
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) throw new Error('Fecha de alerta inválida');

  const rule = findRule(sensor, sid);
  return {
    sensor,
    timestamp: date.toISOString(),
    gid, sid, rev,
    message: String(message ?? '').slice(0, 200),
    classification, priority,
    protocol: protocol ? String(protocol).toUpperCase() : null,
    srcIp, srcPort, dstIp, dstPort,
    objective: rule?.objective ?? null, // a qué prueba de la práctica corresponde
    localRule: Boolean(rule),           // true si es una de nuestras reglas (no de la comunidad)
    raw,
    extra,
  };
}
