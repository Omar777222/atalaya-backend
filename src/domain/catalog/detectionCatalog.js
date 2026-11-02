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
  // SID 1000001-1000003: las 3 reglas que pide la práctica 2.4/2.5 (ICMP, sniffer, herramienta a elección)
  {
    sensor: Sensors.SNORT, sid: 1000001, rev: 1, objective: 'icmp', file: 'local.rules',
    text: 'alert icmp any any -> $HOME_NET any (msg:"ATALAYA SNORT ICMP de prueba"; classtype:misc-activity; sid:1000001; rev:1;)',
    trigger: 'ping -c 4 desde ec2-frontend (host de prueba) hacia la IP privada del backend (sensor).',
    reason: 'Todo paquete ICMP cuyo destino esté en HOME_NET (subred 10.0.128.0/24) coincide. La respuesta del sensor va hacia 10.0.0.10, fuera de HOME_NET, por eso no se duplica.',
  },
  {
    sensor: Sensors.SNORT, sid: 1000002, rev: 1, objective: 'sniffer', file: 'local.rules',
    text: 'alert udp $HOME_NET any -> any 53 (msg:"ATALAYA SNORT DNS PTR - posible sniffer con resolucion de nombres"; content:"|07|in-addr|04|arpa|00|"; nocase; classtype:policy-violation; sid:1000002; rev:1;)',
    trigger: 'tshark/Wireshark en el backend con resolución de nombres activa (-N nN): pregunta al DNS de la VPC el nombre de cada IP que ve (consultas PTR).',
    reason: 'Un sniffer es pasivo y no deja firma propia, pero con resolución de nombres genera consultas DNS inversas. "|07|in-addr|04|arpa|00|" es in-addr.arpa en formato DNS. Es un indicio, no una certeza: con -n (sin resolución) la alerta no aparece.',
  },
  {
    sensor: Sensors.SNORT, sid: 1000003, rev: 1, objective: 'nmap', file: 'local.rules',
    text: 'alert tcp any any -> $HOME_NET any (msg:"ATALAYA SNORT Posible escaneo SYN de puertos (nmap)"; flags:S; detection_filter:track by_src, count 20, seconds 5; classtype:attempted-recon; sid:1000003; rev:1;)',
    trigger: 'sudo nmap -sS -p 1-200 contra el backend desde ec2-frontend: cientos de SYN a puertos distintos en pocos segundos.',
    reason: 'Un cliente normal abre pocas conexiones. detection_filter solo alerta cuando el mismo origen supera 20 SYN en 5 s, que es la huella de un escaneo.',
  },
  // Ampliación (SID 1000004 en adelante)
  {
    sensor: Sensors.SNORT, sid: 1000004, rev: 1, objective: 'sniffer', file: 'local.rules',
    text: 'alert tcp any any -> $HOME_NET 3000 (msg:"ATALAYA SNORT Credenciales en texto claro hacia la API"; flow:to_server,established; content:"|22|password|22|"; nocase; classtype:policy-violation; sid:1000004; rev:1;)',
    trigger: 'Un inicio de sesión en el sitio: Nginx reenvía el JSON con la contraseña a 10.0.128.10:3000 por HTTP.',
    reason: 'El TLS termina en el ALB/Nginx; el tramo interno por el peering viaja sin cifrar. Lo que se ve con Wireshark en el .pcap lo ve Snort en la carga útil.',
  },
  {
    sensor: Sensors.SNORT, sid: 1000005, rev: 1, objective: 'web', file: 'local.rules',
    text: 'alert tcp any any -> $HOME_NET 3000 (msg:"ATALAYA SNORT Posible fuerza bruta al login"; flow:to_server,established; content:"POST"; depth:4; content:"/api/auth/login"; within:30; detection_filter:track by_src, count 5, seconds 60; classtype:attempted-user; sid:1000005; rev:1;)',
    trigger: 'Más de 5 intentos de login en 60 segundos contra la API.',
    reason: 'detection_filter solo alerta a partir del sexto intento en la ventana: un usuario que se equivoca una vez no la dispara.',
  },
  {
    sensor: Sensors.SNORT, sid: 1000006, rev: 1, objective: 'web', file: 'local.rules',
    text: 'alert tcp any any -> $HOME_NET 3000 (msg:"ATALAYA SNORT Herramienta sqlmap (User-Agent)"; flow:to_server,established; content:"User-Agent|3A| sqlmap"; nocase; classtype:web-application-attack; sid:1000006; rev:1;)',
    trigger: 'sqlmap con su User-Agent por defecto contra la API.',
    reason: 'sqlmap se identifica como "sqlmap/1.x". Es fácil de evadir (--random-agent), por eso se complementa con la regla 1000007.',
  },
  {
    sensor: Sensors.SNORT, sid: 1000007, rev: 1, objective: 'web', file: 'local.rules',
    text: 'alert tcp any any -> $HOME_NET 3000 (msg:"ATALAYA SNORT Inyeccion SQL UNION SELECT"; flow:to_server,established; content:"UNION"; nocase; content:"SELECT"; nocase; distance:0; classtype:web-application-attack; sid:1000007; rev:1;)',
    trigger: 'Las cargas útiles de sqlmap que prueban UNION ... SELECT en los parámetros.',
    reason: 'Detecta el contenido del ataque y no la herramienta: sigue funcionando aunque se cambie el User-Agent.',
  },

  // ---------------- Suricata (NIDS en ec2-frontend) -> /var/lib/suricata/rules/ (guía 2.6) ----------------
  // Sensor 1: Nmap (1000001-1000099)
  {
    sensor: Sensors.SURICATA, sid: 1000001, rev: 1, objective: 'nmap', file: 'sensor1-nmap.rules',
    text: 'alert tcp any any -> $HOME_NET any (msg:"ATALAYA S1 Escaneo SYN (Nmap)"; flags:S,12; threshold:type both, track by_src, count 20, seconds 5; classtype:attempted-recon; sid:1000001; rev:1;)',
    trigger: 'nmap -sS -p 1-1000 desde Kali contra la IP pública del frontend.',
    reason: 'Muchos SYN desde una sola IP en 5 s. flags:S,12 ignora los bits ECN; threshold "both" emite una alerta por ventana.',
  },
  {
    sensor: Sensors.SURICATA, sid: 1000002, rev: 1, objective: 'icmp', file: 'sensor1-nmap.rules',
    text: 'alert icmp any any -> $HOME_NET any (msg:"ATALAYA S1 Barrido ICMP (ping / Nmap -sn)"; itype:8; threshold:type both, track by_src, count 5, seconds 5; classtype:attempted-recon; sid:1000002; rev:1;)',
    trigger: 'ping -c 10 desde Kali a la IP pública del frontend (AWS la traduce a la privada 10.0.0.10).',
    reason: '5 echo request (tipo 8) en 5 s desde el mismo origen hacia HOME_NET (10.0.0.0/17).',
  },
  {
    sensor: Sensors.SURICATA, sid: 1000003, rev: 1, objective: 'nmap', file: 'sensor1-nmap.rules',
    text: 'alert http any any -> $HOME_NET any (msg:"ATALAYA S1 Nmap Scripting Engine"; flow:to_server,established; http.user_agent; content:"Nmap Scripting Engine"; nocase; classtype:web-application-attack; sid:1000003; rev:1;)',
    trigger: 'nmap -sV -sC -p 80: los scripts NSE hacen peticiones HTTP con su propio User-Agent.',
    reason: 'NSE se anuncia como "Mozilla/5.0 (compatible; Nmap Scripting Engine)" en http.user_agent.',
  },
  // Sensor 2: tráfico capturado con Wireshark (1000100-1000199)
  {
    sensor: Sensors.SURICATA, sid: 1000100, rev: 1, objective: 'sniffer', file: 'sensor2-wireshark.rules',
    text: 'alert http any any -> $HOME_NET any (msg:"ATALAYA S2 Credenciales en HTTP POST (texto claro)"; flow:to_server,established; http.method; content:"POST"; http.request_body; content:"password"; nocase; classtype:policy-violation; sid:1000100; rev:1;)',
    trigger: 'Un POST de login por HTTP (puerto 80) directo al frontend, el mismo que se analiza en Wireshark con Follow TCP Stream y en modo offline (-r lab.pcap).',
    reason: 'Suricata decodifica HTTP y busca "password" en el cuerpo. Por HTTPS (como desde el ALB) no podría leerlo: demuestra por qué cifrar.',
  },
  {
    sensor: Sensors.SURICATA, sid: 1000102, rev: 1, objective: 'sniffer', file: 'sensor2-wireshark.rules',
    text: 'alert http $HOME_NET any -> 10.0.128.0/17 3000 (msg:"ATALAYA S2 Credenciales en claro hacia el backend (peering)"; flow:to_server,established; http.uri; content:"/api/auth/login"; http.request_body; content:"password"; nocase; classtype:policy-violation; sid:1000102; rev:1;)',
    trigger: 'Un inicio de sesión normal en https://atalaya-zt.duckdns.org: Nginx descifra y reenvía el JSON por HTTP al backend.',
    reason: 'El usuario ve HTTPS, pero el tramo Nginx → API va en claro. Suricata lo ve salir por ens5; por eso la regla mira hacia la red del backend.',
  },
  // Sensor 3: SQLMap (1000200-1000299)
  {
    sensor: Sensors.SURICATA, sid: 1000200, rev: 1, objective: 'web', file: 'sensor3-sqlmap.rules',
    text: 'alert http any any -> $HOME_NET any (msg:"ATALAYA S3 SQLMap User-Agent"; flow:to_server,established; http.user_agent; content:"sqlmap"; nocase; classtype:web-application-attack; sid:1000200; rev:1;)',
    trigger: 'sqlmap por HTTP directo al frontend con el User-Agent por defecto.',
    reason: 'Firma de la herramienta en el encabezado User-Agent; desaparece con --random-agent.',
  },
  {
    sensor: Sensors.SURICATA, sid: 1000201, rev: 1, objective: 'web', file: 'sensor3-sqlmap.rules',
    text: 'alert http any any -> $HOME_NET any (msg:"ATALAYA S3 SQLi UNION SELECT en URI"; flow:to_server,established; http.uri; content:"union"; nocase; content:"select"; nocase; distance:0; classtype:web-application-attack; sid:1000201; rev:1;)',
    trigger: 'Pruebas UNION de sqlmap en el parámetro de la URL.',
    reason: 'http.uri está normalizado (decodifica %20, +), así que detecta el patrón aunque venga codificado.',
  },
  {
    sensor: Sensors.SURICATA, sid: 1000202, rev: 1, objective: 'web', file: 'sensor3-sqlmap.rules',
    text: 'alert http any any -> $HOME_NET any (msg:"ATALAYA S3 SQLi comilla + OR/AND"; flow:to_server,established; http.uri; pcre:"/(\\x27|%27)(\\s|\\+|%20)*(or|and)(\\s|\\+|%20)/i"; classtype:web-application-attack; sid:1000202; rev:1;)',
    trigger: 'Pruebas booleanas de sqlmap: una comilla seguida de OR o AND en el parámetro.',
    reason: 'La expresión regular reconoce la estructura de una inyección booleana sin importar la herramienta.',
  },
  {
    sensor: Sensors.SURICATA, sid: 1000203, rev: 1, objective: 'web', file: 'sensor3-sqlmap.rules',
    text: 'alert http any any -> $HOME_NET any (msg:"ATALAYA S3 SQLi basada en tiempo (SLEEP)"; flow:to_server,established; http.uri; content:"sleep"; nocase; classtype:web-application-attack; sid:1000203; rev:1;)',
    trigger: 'Pruebas time-based de sqlmap (SLEEP(5)) en la URL.',
    reason: 'Es contenido del ataque: sigue disparando con --random-agent.',
  },
];

export const ruleKey = (sensor, sid) => `${sensor}:${sid}`;
const RULE_INDEX = new Map(RULES.map((r) => [ruleKey(r.sensor, r.sid), r]));
export const findRule = (sensor, sid) => RULE_INDEX.get(ruleKey(sensor, sid)) ?? null;
