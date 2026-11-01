// Cómo se explica cada tipo de detección a un CLIENTE (sin jerga técnica ni IPs internas).
export const CLIENT_CATEGORIES = {
  icmp: {
    label: 'Reconocimiento con ping',
    impact: 'Alguien comprobó si tu servidor responde. Suele ser el primer paso antes de un ataque.',
    action: 'Sin riesgo directo. Seguimos vigilando si el mismo origen continúa con otras pruebas.',
  },
  nmap: {
    label: 'Escaneo de puertos',
    impact: 'Buscaron qué servicios tiene abiertos tu servidor para encontrar una entrada.',
    action: 'Solo están abiertos los puertos necesarios (Security Groups y UFW). Revisamos el origen.',
  },
  sniffer: {
    label: 'Datos sensibles sin cifrar',
    impact: 'Una contraseña viajó por HTTP en algún tramo de la red y podría ser leída con un sniffer.',
    action: 'Recomendación: cifrar también el tramo interno (TLS de Nginx hasta la API).',
  },
  web: {
    label: 'Ataque a la aplicación web',
    impact: 'Intentos de inyección SQL o de adivinar contraseñas en el inicio de sesión.',
    action: 'AWS WAF y Fail2Ban bloquean estos intentos y la API valida cada dato que recibe.',
  },
  other: {
    label: 'Otras detecciones',
    impact: 'Alertas de reglas de la comunidad (tráfico sospechoso conocido).',
    action: 'El equipo de seguridad las revisa en el centro de monitoreo.',
  },
};
