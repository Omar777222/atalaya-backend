#!/usr/bin/env bash
# Da permiso de LECTURA de las alertas de Snort al usuario que ejecuta la API (sin hacerlo root).
# Uso: sudo bash permisos-snort.sh [usuario]   (si no se indica, se toma del servicio atalaya-backend)
set -e
U=${1:-$(systemctl show -p User --value atalaya-backend)}
[ -z "$U" ] && { echo "No se pudo detectar el usuario de atalaya-backend; pásalo como argumento"; exit 1; }
apt-get install -y acl >/dev/null
touch /var/log/snort/alert_fast.txt
setfacl -m u:"$U":rx /var/log/snort
setfacl -m u:"$U":r /var/log/snort/alert_fast.txt
setfacl -d -m u:"$U":r /var/log/snort      # archivos nuevos (logrotate) heredan el permiso
sudo -u "$U" head -c 0 /var/log/snort/alert_fast.txt && echo "OK: $U puede leer /var/log/snort/alert_fast.txt"
