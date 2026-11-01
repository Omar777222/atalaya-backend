#!/usr/bin/env bash
# Respaldo diario de la base atalaya (formato custom de pg_dump) con 7 días de retención.
# Instalar:  sudo cp db/respaldo-postgresql.sh /usr/local/bin/atalaya-respaldo && sudo chmod 700 /usr/local/bin/atalaya-respaldo
#            echo '30 3 * * * root /usr/local/bin/atalaya-respaldo' | sudo tee /etc/cron.d/atalaya-respaldo
# Restaurar: sudo -u postgres pg_restore --clean -d atalaya /var/backups/atalaya/atalaya-AAAAMMDD-HHMM.dump
set -euo pipefail
DIR=/var/backups/atalaya
mkdir -p "$DIR" && chmod 700 "$DIR"
FILE="$DIR/atalaya-$(date +%Y%m%d-%H%M).dump"
sudo -u postgres pg_dump -Fc atalaya > "$FILE"
chmod 600 "$FILE"
find "$DIR" -name 'atalaya-*.dump' -mtime +7 -delete
echo "Respaldo creado: $FILE ($(du -h "$FILE" | cut -f1))"
