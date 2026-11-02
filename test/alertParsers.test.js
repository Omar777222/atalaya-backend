import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseFastLine, fromEveAlert } from '../src/infrastructure/ids/alertParsers.js';
import { createIdsAlert } from '../src/domain/entities/IdsAlert.js';

test('parsea una alerta ICMP de Snort 2 (sin año)', () => {
  const a = parseFastLine('10/31-18:20:01.123456  [**] [1:1000001:1] ATALAYA SNORT ICMP de prueba (ping) [**] [Classification: Misc activity] [Priority: 3] {ICMP} 10.0.0.10 -> 10.0.128.10', { now: new Date(2026, 9, 31, 19) });
  assert.equal(a.sid, 1000001);
  assert.equal(a.protocol, 'ICMP');
  assert.equal(a.srcIp, '10.0.0.10');
  assert.equal(a.dstPort, null);
  assert.equal(a.priority, 3);
  assert.equal(new Date(a.timestamp).getFullYear(), 2026);
});

test('parsea TCP con puertos y fecha de Suricata (con año)', () => {
  const a = parseFastLine('10/31/2026-18:20:01.000001  [**] [1:1000001:1] ATALAYA S1 Escaneo SYN (Nmap) [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 189.203.14.77:61022 -> 10.0.0.10:443', { sensor: 'suricata' });
  assert.equal(a.srcPort, 61022);
  assert.equal(a.dstIp, '10.0.0.10');
  assert.equal(a.classification, 'Attempted Information Leak');
});

test('ignora líneas que no son alertas', () => {
  assert.equal(parseFastLine('basura'), null);
});

test('convierte un evento de eve.json y lo asocia al objetivo', () => {
  const alert = createIdsAlert(fromEveAlert({ timestamp: '2026-10-31T18:20:01.123456+0000', src_ip: '1.2.3.4', dest_ip: '10.0.0.10', proto: 'ICMP', alert: { signature_id: 1000002, signature: 'x', severity: 3 } }));
  assert.equal(alert.objective, 'icmp');
  assert.equal(alert.timestamp, '2026-10-31T18:20:01.123Z');
});

import { validateSuricataEvents } from '../src/infrastructure/http/validators.js';
import { RULES } from '../src/domain/catalog/detectionCatalog.js';

test('valida y recorta eventos de eve.json', () => {
  const [e] = validateSuricataEvents({ events: [{ timestamp: '2026-10-31T18:20:01.1+0000', event_type: 'alert', src_ip: '1.2.3.4', dest_ip: '10.0.0.10', proto: 'TCP', alert: { signature_id: 1100001, signature: 'x' }, payload: 'AAAA' }] });
  assert.equal(e.payload, undefined);
  assert.throws(() => validateSuricataEvents({ events: [] }));
  assert.throws(() => validateSuricataEvents({ events: [{ event_type: 'flow' }] }));
});

test('cada regla del catálogo tiene sid y rev coherentes y no se repite', () => {
  for (const r of RULES) {
    assert.match(r.text, new RegExp(`sid:${r.sid};`));
    assert.match(r.text, new RegExp(`rev:${r.rev};`));
    assert.match(r.text, /^alert /);
    assert.ok(r.trigger && r.reason && r.file);
  }
  const keys = RULES.map((r) => `${r.sensor}:${r.sid}`);
  assert.equal(new Set(keys).size, keys.length);
});

import { GetClientSummary } from '../src/application/use-cases/GetClientSummary.js';

test('el resumen del cliente agrupa por categoría y no expone IPs', async () => {
  const alerts = [
    { sensor: 'snort', sid: 1000003, objective: 'nmap', priority: 2, srcIp: '10.0.0.10', timestamp: new Date().toISOString() },
    { sensor: 'suricata', sid: 1000200, objective: 'web', priority: 1, srcIp: '1.2.3.4', timestamp: new Date().toISOString() },
  ];
  const uc = new GetClientSummary({
    alertStore: { all: async () => alerts },
    sensorMonitor: { status: async () => ({ service: 'active' }) },
    service: { name: 'Atalaya SOC', site: 'x' },
  });
  const r = await uc.execute();
  assert.equal(r.stats.today, 2);
  assert.equal(r.stats.sources, 2);
  assert.equal(r.status, 'atencion');
  assert.equal(r.incidents.length, 2);
  assert.ok(!JSON.stringify(r.incidents).includes('10.0.0.10'));
});
