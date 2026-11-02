// SOLO PARA DESARROLLO LOCAL: simula alertas para ver la interfaz sin AWS.
// En AWS las alertas las escriben Snort y Suricata de verdad: NO uses este script como evidencia.
//
// Uso (con la API corriendo en local):
//   npm run demo -- all        todas las pruebas
//   npm run demo -- ping | wireshark | nmap | sqlmap
//   npm run demo -- latido     mantiene "en línea" a Suricata (latido cada 20 s)
import 'dotenv/config';
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const API = process.env.DEMO_API ?? `http://127.0.0.1:${process.env.PORT ?? 3000}/api/internal`;
const KEY = process.env.IDS_INGEST_KEY;
const SNORT_FILE = process.env.IDS_SNORT_ALERT_FILE;
const KALI = '189.203.14.77';
const FRONT = process.env.IDS_FRONTEND_PRIVATE_IP ?? '10.0.0.10';
const BACK = process.env.IDS_BACKEND_PRIVATE_IP ?? '10.0.128.10';

if (!KEY || !SNORT_FILE) {
  console.error('Faltan IDS_INGEST_KEY o IDS_SNORT_ALERT_FILE en el .env');
  process.exit(1);
}
if (SNORT_FILE.startsWith('/var/log')) {
  console.error('IDS_SNORT_ALERT_FILE apunta al log real de Snort. Este script es solo para local (usa ./samples/alert_fast.txt).');
  process.exit(1);
}

const p2 = (n) => String(n).padStart(2, '0');
const fastTime = (d) => `${p2(d.getMonth() + 1)}/${p2(d.getDate())}-${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}.${String(d.getMilliseconds() * 1000).padStart(6, '0')}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function snort(sid, msg, cls, prio, proto, src, dst) {
  mkdirSync(dirname(SNORT_FILE), { recursive: true });
  appendFileSync(SNORT_FILE, `${fastTime(new Date())}  [**] [1:${sid}:1] ${msg} [**] [Classification: ${cls}] [Priority: ${prio}] {${proto}} ${src} -> ${dst}\n`);
}

async function post(path, body) {
  const res = await fetch(`${API}${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Atalaya-Key': KEY }, body: JSON.stringify(body) });
  if (!res.ok) throw new Error(`${path} respondió ${res.status}: ${await res.text()}`);
}

const eve = (sid, signature, category, severity, proto, srcPort, destPort, http) => ({
  event_type: 'alert', timestamp: new Date().toISOString().replace('Z', '+0000'),
  src_ip: KALI, src_port: srcPort, dest_ip: FRONT, dest_port: destPort, proto,
  alert: { gid: 1, signature_id: sid, rev: 1, signature, category, severity }, http,
});

const heartbeat = () => post('/ids/heartbeat', { sensor: 'suricata', service: 'active', version: 'Suricata 7 (demo local)', host: 'ec2-frontend', telegram: 'ok', log: { path: '/var/log/suricata/eve.json', status: 'ok' } });

const SCENARIOS = {
  async ping() {
    for (let i = 0; i < 4; i += 1) {
      await post('/ids/suricata', { events: [eve(1000002, 'ATALAYA S1 Barrido ICMP (ping / Nmap -sn)', 'Misc activity', 3, 'ICMP', null, null)] });
      snort(1000001, 'ATALAYA SNORT ICMP de prueba', 'Misc activity', 3, 'ICMP', FRONT, BACK);
      await sleep(700);
    }
  },
  async wireshark() {
    await post('/ids/suricata', { events: [eve(1000102, 'ATALAYA S2 Credenciales en claro hacia el backend (peering)', 'Potential Corporate Privacy Violation', 1, 'TCP', 40122, 3000, { hostname: '10.0.128.10', url: '/api/auth/login', http_method: 'POST', http_user_agent: 'Mozilla/5.0' })].map((e) => ({ ...e, src_ip: FRONT, dest_ip: BACK })) });
    await post('/ids/suricata', { events: [eve(1000100, 'ATALAYA S2 Credenciales en HTTP POST (texto claro)', 'Potential Corporate Privacy Violation', 1, 'TCP', 51544, 80, { hostname: '52.54.234.146', url: '/api/auth/login', http_method: 'POST', http_user_agent: 'curl/8.5.0', status: 301 })] });
    snort(1000002, 'ATALAYA SNORT DNS PTR - posible sniffer con resolucion de nombres', 'Potential Corporate Privacy Violation', 1, 'UDP', `${BACK}:41522`, '10.0.128.2:53');
    snort(1000004, 'ATALAYA SNORT Credenciales en texto claro hacia la API', 'Potential Corporate Privacy Violation', 1, 'TCP', `${FRONT}:43870`, `${BACK}:3000`);
  },
  async nmap() {
    await post('/ids/suricata', { events: [eve(1000001, 'ATALAYA S1 Escaneo SYN (Nmap)', 'Attempted Information Leak', 2, 'TCP', 61022, 443)] });
    snort(1000003, 'ATALAYA SNORT Posible escaneo SYN de puertos (nmap)', 'Attempted Information Leak', 2, 'TCP', `${FRONT}:58113`, `${BACK}:22`);
    await sleep(900);
    await post('/ids/suricata', { events: [eve(1000003, 'ATALAYA S1 Nmap Scripting Engine', 'Web Application Attack', 1, 'TCP', 61040, 80, { hostname: '52.54.234.146', url: '/', http_method: 'GET', http_user_agent: 'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)', status: 301 })] });
  },
  async sqlmap() {
    await post('/ids/suricata', { events: [
      eve(1000200, 'ATALAYA S3 SQLMap User-Agent', 'Web Application Attack', 1, 'TCP', 52210, 80, { url: '/api/health?check=1', http_method: 'GET', http_user_agent: 'sqlmap/1.8.4#stable (https://sqlmap.org)' }),
      eve(1000201, 'ATALAYA S3 SQLi UNION SELECT en URI', 'Web Application Attack', 1, 'TCP', 52211, 80, { url: '/api/health?check=1 UNION ALL SELECT NULL--', http_method: 'GET', http_user_agent: 'sqlmap/1.8.4#stable (https://sqlmap.org)' }),
      eve(1000203, 'ATALAYA S3 SQLi basada en tiempo (SLEEP)', 'Web Application Attack', 1, 'TCP', 52212, 80, { url: '/api/health?check=1 AND SLEEP(5)', http_method: 'GET', http_user_agent: 'sqlmap/1.8.4#stable (https://sqlmap.org)' }),
    ] });
    snort(1000006, 'ATALAYA SNORT Herramienta sqlmap (User-Agent)', 'Web Application Attack', 1, 'TCP', `${FRONT}:44120`, `${BACK}:3000`);
    snort(1000007, 'ATALAYA SNORT Inyeccion SQL UNION SELECT', 'Web Application Attack', 1, 'TCP', `${FRONT}:44121`, `${BACK}:3000`);
    snort(1000005, 'ATALAYA SNORT Posible fuerza bruta al login', 'Attempted User Privilege Gain', 1, 'TCP', `${FRONT}:44188`, `${BACK}:3000`);
  },
};

const arg = process.argv[2] ?? 'all';
await heartbeat();
if (arg === 'latido') {
  console.log('Enviando latido de Suricata cada 20 s (Ctrl+C para salir)…');
  setInterval(() => heartbeat().catch((e) => console.error(e.message)), 20000);
} else {
  const list = arg === 'all' ? Object.keys(SCENARIOS) : [arg];
  for (const name of list) {
    if (!SCENARIOS[name]) { console.error(`Escenario desconocido: ${name}`); process.exit(1); }
    console.log(`Simulando: ${name}`);
    await SCENARIOS[name]();
    await sleep(1200);
  }
  console.log('Listo. Recuerda: son alertas simuladas para desarrollo local.');
}
