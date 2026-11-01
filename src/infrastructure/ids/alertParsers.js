import { Sensors } from '../../domain/catalog/detectionCatalog.js';

// Formato "fast" de Snort 2 (output alert_fast) y de Suricata (fast.log):
// 10/31-18:20:01.123456  [**] [1:1000001:1] Mensaje [**] [Classification: Misc activity] [Priority: 3] {ICMP} 10.0.0.10 -> 10.0.128.10
// Suricata agrega el año: 10/31/2026-18:20:01.123456
const FAST_RE = new RegExp(
  '^(\\d{2})/(\\d{2})(?:/(\\d{2,4}))?-(\\d{2}):(\\d{2}):(\\d{2})(?:\\.(\\d{1,6}))?\\s+' +
  '\\[\\*\\*\\]\\s+\\[(\\d+):(\\d+):(\\d+)\\]\\s+(.*?)\\s+\\[\\*\\*\\]' +
  '(?:\\s+\\[Classification:\\s*([^\\]]*)\\])?' +
  '(?:\\s+\\[Priority:\\s*(\\d+)\\])?' +
  '\\s+\\{([^}]+)\\}\\s+(\\S+)\\s+->\\s+(\\S+)\\s*$',
);

// "10.0.0.10:443" -> { ip, port } ; "10.0.0.10" -> { ip, port: null }
function splitEndpoint(value) {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(value);
  if (m) return { ip: m[1], port: Number(m[2]) };
  return { ip: value, port: null };
}

export function parseFastLine(line, { sensor = Sensors.SNORT, now = new Date() } = {}) {
  const m = FAST_RE.exec(line.trim());
  if (!m) return null;
  const [, mon, day, yearRaw, hh, mm, ss, frac = '0', gid, sid, rev, message, classification, priority, proto, src, dst] = m;

  let year = yearRaw ? Number(yearRaw.length === 2 ? `20${yearRaw}` : yearRaw) : now.getFullYear();
  const ms = Math.floor(Number(frac.padEnd(6, '0')) / 1000);
  // Hora local del servidor: es la misma zona en la que escribe Snort
  let date = new Date(year, Number(mon) - 1, Number(day), Number(hh), Number(mm), Number(ss), ms);
  if (!yearRaw && date.getTime() - now.getTime() > 24 * 3600 * 1000) {
    year -= 1; // cambio de año (alerta de diciembre leída en enero)
    date = new Date(year, Number(mon) - 1, Number(day), Number(hh), Number(mm), Number(ss), ms);
  }

  const s = splitEndpoint(src);
  const d = splitEndpoint(dst);
  return {
    sensor,
    timestamp: date.toISOString(),
    gid: Number(gid), sid: Number(sid), rev: Number(rev),
    message,
    classification: classification?.trim() || null,
    priority: priority ? Number(priority) : null,
    protocol: proto,
    srcIp: s.ip, srcPort: s.port, dstIp: d.ip, dstPort: d.port,
    raw: line.trim().slice(0, 600),
  };
}

// Evento "alert" de eve.json (Suricata) que envía el agente del frontend.
// Suricata escribe la zona como +0000; JavaScript necesita +00:00.
const fixOffset = (ts) => String(ts).replace(/([+-]\d{2})(\d{2})$/, '$1:$2');

export function fromEveAlert(e) {
  const extra = e.http
    ? { url: e.http.url ?? null, method: e.http.http_method ?? null, userAgent: e.http.http_user_agent ?? null, hostname: e.http.hostname ?? null }
    : null;
  return {
    sensor: Sensors.SURICATA,
    timestamp: fixOffset(e.timestamp),
    gid: e.alert.gid ?? 1,
    sid: e.alert.signature_id,
    rev: e.alert.rev ?? 1,
    message: e.alert.signature,
    classification: e.alert.category || null,
    priority: e.alert.severity ?? null,
    protocol: e.proto ?? null,
    srcIp: e.src_ip ?? null,
    srcPort: e.src_port ?? null,
    dstIp: e.dest_ip ?? null,
    dstPort: e.dest_port ?? null,
    raw: JSON.stringify(e).slice(0, 1200), // el evento de eve.json tal como llegó (recortado)
    extra,
  };
}
