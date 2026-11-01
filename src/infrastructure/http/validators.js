import { ValidationError } from '../../domain/errors/DomainErrors.js';
import { SecurityEventTypes } from '../../domain/entities/SecurityEvent.js';
import { Sensors, OBJECTIVES } from '../../domain/catalog/detectionCatalog.js';

const USERNAME_RE = /^[a-zA-Z0-9._-]{3,30}$/;

export function validateCredentials(body) {
  const { username, password } = body ?? {};
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) {
    throw new ValidationError('El usuario solo admite letras, números y . _ - (3 a 30 caracteres)');
  }
  if (typeof password !== 'string' || password.length < 1 || password.length > 128) {
    throw new ValidationError('La contraseña tiene un formato inválido');
  }
  return { username, password };
}

export function validateAuditFilters(query) {
  const limit = query.limit === undefined ? 50 : Number(query.limit);
  if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
    throw new ValidationError('El límite debe ser un número entre 1 y 200');
  }
  const type = query.type || undefined;
  if (type && !SecurityEventTypes[type]) {
    throw new ValidationError('Tipo de evento no válido');
  }
  return { limit, type };
}

// ---------- IDS ----------
const SENSOR_SET = new Set(Object.values(Sensors));
const OBJECTIVE_SET = new Set(OBJECTIVES.map((o) => o.id));
const IP_RE = /^[0-9a-fA-F:.]{2,45}$/;

const optionalInt = (value, { min, max, name }) => {
  if (value === undefined || value === '') return undefined;
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) throw new ValidationError(`${name} debe ser un entero entre ${min} y ${max}`);
  return n;
};

export function validateAlertFilters(query) {
  const sensor = query.sensor || undefined;
  if (sensor && !SENSOR_SET.has(sensor)) throw new ValidationError('Sensor no válido (snort o suricata)');
  const objective = query.objective || undefined;
  if (objective && !OBJECTIVE_SET.has(objective)) throw new ValidationError('Objetivo no válido');
  const limit = optionalInt(query.limit, { min: 1, max: 500, name: 'El límite' }) ?? 100;
  const after = optionalInt(query.after, { min: 0, max: Number.MAX_SAFE_INTEGER, name: 'El cursor' });
  return { sensor, objective, limit, after };
}

export function validateFeedQuery(query) {
  const after = optionalInt(query.after, { min: 0, max: Number.MAX_SAFE_INTEGER, name: 'El cursor' });
  const limit = optionalInt(query.limit, { min: 1, max: 200, name: 'El límite' }) ?? 50;
  return { after, limit };
}

const str = (v, max) => (typeof v === 'string' ? v.slice(0, max) : null);
const port = (v) => (Number.isInteger(v) && v >= 0 && v <= 65535 ? v : null);
const ip = (v) => (typeof v === 'string' && IP_RE.test(v) ? v : null);

// Solo se aceptan los campos necesarios de cada evento de eve.json
export function validateSuricataEvents(body) {
  const events = body?.events;
  if (!Array.isArray(events) || events.length < 1 || events.length > 100) {
    throw new ValidationError('Se esperaba "events" con 1 a 100 alertas de eve.json');
  }
  return events.map((e, i) => {
    const a = e?.alert;
    if (e?.event_type !== 'alert' || typeof a !== 'object' || a === null) throw new ValidationError(`El evento ${i} no es una alerta`);
    if (!Number.isInteger(a.signature_id)) throw new ValidationError(`El evento ${i} no tiene signature_id`);
    if (typeof e.timestamp !== 'string' || e.timestamp.length > 40) throw new ValidationError(`El evento ${i} no tiene timestamp`);
    return {
      timestamp: e.timestamp,
      event_type: 'alert',
      src_ip: ip(e.src_ip), src_port: port(e.src_port),
      dest_ip: ip(e.dest_ip), dest_port: port(e.dest_port),
      proto: str(e.proto, 12),
      alert: {
        gid: Number.isInteger(a.gid) ? a.gid : 1,
        signature_id: a.signature_id,
        rev: Number.isInteger(a.rev) ? a.rev : 1,
        signature: str(a.signature, 200) ?? `SID ${a.signature_id}`,
        category: str(a.category, 100),
        severity: Number.isInteger(a.severity) ? a.severity : null,
      },
      http: e.http && typeof e.http === 'object' ? {
        hostname: str(e.http.hostname, 120),
        url: str(e.http.url, 300),
        http_user_agent: str(e.http.http_user_agent, 200),
        http_method: str(e.http.http_method, 10),
      } : undefined,
    };
  });
}

export function validateHeartbeat(body) {
  const sensor = body?.sensor;
  if (sensor !== Sensors.SURICATA) throw new ValidationError('Solo Suricata envía latidos remotos');
  const service = str(body.service, 20) ?? 'unknown';
  const version = str(body.version, 60);
  const telegram = str(body.telegram, 20);
  const log = body.log && typeof body.log === 'object' ? {
    path: str(body.log.path, 120),
    status: str(body.log.status, 20),
    error: str(body.log.error, 60),
  } : null;
  return { sensor, service, version, log, telegram };
}
