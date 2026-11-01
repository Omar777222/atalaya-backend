// Catálogo de detección de Atalaya: qué prueba de la práctica cubre cada regla,
// en qué sensor vive y cómo se explica. Es la misma información que va en los archivos
// de reglas de la carpeta ids/ (se generan con: npm run rules:export).

export const Sensors = Object.freeze({
  SURICATA: 'suricata',
  SNORT: 'snort',
});

// Las pruebas que pide la actividad 2.4 (objetivos de validación) + una de ampliación
export const OBJECTIVES = [
  {
    id: 'icmp',
    order: 1,
    title: 'Objetivo 1 · ICMP (ping)',
    tool: 'ping',
    summary: 'Generar alertas ICMP simples mediante una regla local.',
  },
  {
    id: 'sniffer',
    order: 2,
    title: 'Objetivo 2 · Sniffer (Wireshark)',
    tool: 'Wireshark / tcpdump',
    summary: 'Wireshark es pasivo: se detecta el tráfico sensible en claro que el sniffer puede leer.',
  },
  {
    id: 'nmap',
    order: 3,
    title: 'Objetivo 3 · Escaneo con Nmap',
    tool: 'nmap',
    summary: 'Reconocimiento previo a un ataque: escaneo de puertos SYN y scripts NSE.',
  },
  {
    id: 'web',
    order: 4,
    title: 'Ampliación · sqlmap y fuerza bruta',
    tool: 'sqlmap / curl',
    summary: 'Ataques a la aplicación web: inyección SQL automatizada y adivinación de contraseñas.',
  },
];

export const RULES = [
  // ---------------- Snort (HIDS en ec2-backend) -> /etc/snort/rules/local.rules ----------------
  {
    sensor: Sensors.SNORT, sid: 1000001, rev: 1, objective: 'icmp', file: 'local.rules',
    text: 'alert icmp any any -> $HOME_NET any (msg:"ATALAYA SNORT ICMP de prueba (ping)"; itype:8; classtype:misc-activity; sid:1000001; rev:1;)',
    trigger: 'Un ping (ICMP echo request, tipo 8) desde el frontend hacia la IP privada del backend.',
    reason: 'La regla vigila cualquier echo request cuyo destino esté en HOME_NET (10.0.128.0/17). itype:8 evita alertar también por las respuestas.',
  },
  {
    sensor: Sensors.SNORT, sid: 1000002, rev: 1, objective: 'nmap', file: 'local.rules',
    text: 'alert tcp any any -> $HOME_NET any (msg:"ATALAYA SNORT Escaneo de puertos SYN (nmap)"; flags:S; threshold:type both, track by_src, count 20, seconds 5; classtype:attempted-recon; sid:1000002; rev:1;)',
    trigger: 'nmap -sS contra el backend: cientos de paquetes SYN a puertos distintos en pocos segundos.',
    reason: 'Un cliente normal abre pocas conexiones. 20 SYN en 5 s desde la misma IP es la huella de un escaneo; threshold "both" emite una sola alerta por ventana para no saturar el log.',
  },
  {
    sensor: Sensors.SNORT, sid: 1000003, rev: 1, objective: 'sniffer', file: 'local.rules',
    text: 'alert tcp any any -> $HOME_NET 3000 (msg:"ATALAYA SNORT Credenciales en texto claro hacia la API"; flow:to_server,established; content:"|22|password|22|"; nocase; classtype:policy-violation; sid:1000003; rev:1;)',
    trigger: 'Un inicio de sesión en el sitio: Nginx reenvía el JSON con la contraseña a 10.0.128.10:3000 por HTTP.',
    reason: 'El TLS termina en el ALB/Nginx; el tramo interno por el peering viaja sin cifrar. Lo mismo que se ve con Wireshark en el .pcap lo ve Snort en la carga útil.',
  },
  {
    sensor: Sensors.SNORT, sid: 1000004, rev: 1, objective: 'web', file: 'local.rules',
    text: 'alert tcp any any -> $HOME_NET 3000 (msg:"ATALAYA SNORT Posible fuerza bruta al login"; flow:to_server,established; content:"POST"; depth:4; content:"/api/auth/login"; within:30; detection_filter:track by_src, count 5, seconds 60; classtype:attempted-user; sid:1000004; rev:1;)',
    trigger: 'Más de 5 intentos de login en 60 segundos (script con curl desde Kali o desde el frontend).',
    reason: 'detection_filter solo alerta a partir del sexto intento en la ventana: un usuario que se equivoca una vez no la dispara.',
  },
  {
    sensor: Sensors.SNORT, sid: 1000005, rev: 1, objective: 'web', file: 'local.rules',
    text: 'alert tcp any any -> $HOME_NET 3000 (msg:"ATALAYA SNORT Herramienta sqlmap (User-Agent)"; flow:to_server,established; content:"User-Agent|3A| sqlmap"; nocase; classtype:web-application-attack; sid:1000005; rev:1;)',
    trigger: 'sqlmap con su User-Agent por defecto; Nginx lo reenvía tal cual a la API.',
    reason: 'sqlmap se identifica como "sqlmap/1.x". Es una firma fácil de evadir (--random-agent), por eso se complementa con la regla 1000006.',
  },
  {
    sensor: Sensors.SNORT, sid: 1000006, rev: 1, objective: 'web', file: 'local.rules',
    text: 'alert tcp any any -> $HOME_NET 3000 (msg:"ATALAYA SNORT Inyeccion SQL UNION SELECT"; flow:to_server,established; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; classtype:web-application-attack; sid:1000006; rev:1;)',
    trigger: 'Las cargas útiles de sqlmap que prueban UNION ... SELECT en los parámetros.',
    reason: 'Detecta el contenido del ataque y no la herramienta: sigue funcionando aunque se cambie el User-Agent.',
  },

  // ---------------- Suricata (NIDS en ec2-frontend) -> /var/lib/suricata/rules/*.rules ----------------
  {
    sensor: Sensors.SURICATA, sid: 1100001, rev: 1, objective: 'icmp', file: 'atalaya-obj1-icmp.rules',
    text: 'alert icmp any any -> $HOME_NET any (msg:"ATALAYA SURICATA ICMP echo request (ping)"; itype:8; classtype:misc-activity; sid:1100001; rev:1;)',
    trigger: 'ping desde Kali a la IP pública del frontend (AWS la traduce a la privada 10.0.0.10).',
    reason: 'Suricata ve el paquete con destino 10.0.0.10, que pertenece a HOME_NET (10.0.0.0/17).',
  },
  {
    sensor: Sensors.SURICATA, sid: 1100101, rev: 1, objective: 'sniffer', file: 'atalaya-obj2-wireshark.rules',
    text: 'alert http any any -> $HOME_NET any (msg:"ATALAYA SURICATA Credenciales en texto claro (HTTP POST)"; flow:to_server,established; http.method; content:"POST"; http.request_body; content:"password"; nocase; classtype:policy-violation; sid:1100101; rev:1;)',
    trigger: 'Un POST de login enviado por HTTP (puerto 80) directo al frontend, el mismo que se analiza en Wireshark con Follow TCP Stream.',
    reason: 'Suricata decodifica HTTP y busca "password" en el cuerpo. Si llegara por HTTPS (como desde el ALB) no podría leerlo: eso demuestra por qué cifrar.',
  },
  {
    sensor: Sensors.SURICATA, sid: 1100102, rev: 1, objective: 'sniffer', file: 'atalaya-obj2-wireshark.rules',
    text: 'alert http $HOME_NET any -> 10.0.128.0/17 3000 (msg:"ATALAYA SURICATA Credenciales en claro hacia el backend (peering)"; flow:to_server,established; http.uri; content:"/api/auth/login"; http.request_body; content:"password"; nocase; classtype:policy-violation; sid:1100102; rev:1;)',
    trigger: 'Un inicio de sesión normal en https://atalaya-zt.duckdns.org: Nginx descifra y reenvía el JSON por HTTP al backend.',
    reason: 'El usuario ve HTTPS, pero el tramo Nginx → API (10.0.128.10:3000) va en claro. Suricata lo ve salir por ens5; por eso esta regla mira hacia la red del backend y no hacia HOME_NET.',
  },
  {
    sensor: Sensors.SURICATA, sid: 1100002, rev: 1, objective: 'nmap', file: 'atalaya-obj3-nmap.rules',
    text: 'alert tcp any any -> $HOME_NET any (msg:"ATALAYA SURICATA Escaneo SYN (nmap)"; flags:S,12; threshold:type both, track by_src, count 20, seconds 5; classtype:attempted-recon; sid:1100002; rev:1;)',
    trigger: 'nmap -sS desde Kali contra la IP pública del frontend.',
    reason: 'Muchos SYN desde una sola IP en 5 s. flags:S,12 ignora los bits ECN para que la regla no falle con pilas TCP modernas.',
  },
  {
    sensor: Sensors.SURICATA, sid: 1100003, rev: 1, objective: 'nmap', file: 'atalaya-obj3-nmap.rules',
    text: 'alert http any any -> $HOME_NET any (msg:"ATALAYA SURICATA Nmap Scripting Engine"; flow:to_server,established; http.user_agent; content:"Nmap Scripting Engine"; nocase; classtype:web-application-attack; sid:1100003; rev:1;)',
    trigger: 'nmap -sV -sC -p 80: los scripts NSE hacen peticiones HTTP con su propio User-Agent.',
    reason: 'NSE se anuncia como "Mozilla/5.0 (compatible; Nmap Scripting Engine)" en http.user_agent.',
  },
  {
    sensor: Sensors.SURICATA, sid: 1100201, rev: 1, objective: 'web', file: 'atalaya-extra-sqlmap.rules',
    text: 'alert http any any -> $HOME_NET any (msg:"ATALAYA SURICATA sqlmap User-Agent"; flow:to_server,established; http.user_agent; content:"sqlmap"; nocase; classtype:web-application-attack; sid:1100201; rev:1;)',
    trigger: 'sqlmap por HTTP directo al frontend con el User-Agent por defecto.',
    reason: 'Firma de la herramienta en el encabezado User-Agent.',
  },
  {
    sensor: Sensors.SURICATA, sid: 1100202, rev: 1, objective: 'web', file: 'atalaya-extra-sqlmap.rules',
    text: 'alert http any any -> $HOME_NET any (msg:"ATALAYA SURICATA SQLi UNION SELECT en URI"; flow:to_server,established; http.uri; content:"union"; nocase; content:"select"; nocase; distance:0; classtype:web-application-attack; sid:1100202; rev:1;)',
    trigger: 'Pruebas UNION de sqlmap en el parámetro de la URL.',
    reason: 'http.uri está normalizado (decodifica %20, +), así que detecta el patrón aunque venga codificado.',
  },
  {
    sensor: Sensors.SURICATA, sid: 1100203, rev: 1, objective: 'web', file: 'atalaya-extra-sqlmap.rules',
    text: 'alert http any any -> $HOME_NET any (msg:"ATALAYA SURICATA SQLi comilla + OR/AND"; flow:to_server,established; http.uri; pcre:"/(\\x27|%27)(\\s|\\+|%20)*(or|and)(\\s|\\+|%20)/i"; classtype:web-application-attack; sid:1100203; rev:1;)',
    trigger: 'Pruebas booleanas de sqlmap: una comilla seguida de OR o AND en el parámetro.',
    reason: 'La expresión regular reconoce la estructura de una inyección booleana sin importar la herramienta.',
  },
  {
    sensor: Sensors.SURICATA, sid: 1100204, rev: 1, objective: 'web', file: 'atalaya-extra-sqlmap.rules',
    text: 'alert http any any -> $HOME_NET any (msg:"ATALAYA SURICATA SQLi basada en tiempo (SLEEP)"; flow:to_server,established; http.uri; content:"sleep"; nocase; classtype:web-application-attack; sid:1100204; rev:1;)',
    trigger: 'Pruebas time-based de sqlmap (SLEEP(5)) en la URL.',
    reason: 'Es contenido del ataque: sigue disparando con --random-agent.',
  },
];

export const ruleKey = (sensor, sid) => `${sensor}:${sid}`;
const RULE_INDEX = new Map(RULES.map((r) => [ruleKey(r.sensor, r.sid), r]));
export const findRule = (sensor, sid) => RULE_INDEX.get(ruleKey(sensor, sid)) ?? null;
