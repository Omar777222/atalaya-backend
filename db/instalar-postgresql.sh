#!/usr/bin/env bash
# Instala y asegura PostgreSQL en ec2-backend. Ejecútalo DURANTE la ventana temporal de internet
# (misma ventana en la que se instala Snort). Uso: sudo bash db/instalar-postgresql.sh
set -euo pipefail

echo "== 1. Memoria de intercambio (t2.micro tiene 1 GB: Node + Snort + PostgreSQL)"
if ! swapon --show | grep -q /swapfile; then
  fallocate -l 1G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
free -h | head -2

echo "== 2. Instalación"
apt-get install -y postgresql postgresql-contrib >/dev/null
systemctl enable --now postgresql
PGVER=$(ls /etc/postgresql | sort -V | tail -1)
CONF=/etc/postgresql/$PGVER/main

echo "== 3. Solo escucha en localhost (la base nunca se expone a la red)"
sed -ri "s/^#?listen_addresses\s*=.*/listen_addresses = 'localhost'/" "$CONF/postgresql.conf"
sed -ri "s/^#?password_encryption\s*=.*/password_encryption = scram-sha-256/" "$CONF/postgresql.conf"
# Conexiones locales por TCP con contraseña cifrada (scram-sha-256); nada desde otras IPs
grep -qE '^host\s+atalaya\s+atalaya\s+127.0.0.1/32' "$CONF/pg_hba.conf" || \
  sed -i "1i host    atalaya    atalaya    127.0.0.1/32    scram-sha-256" "$CONF/pg_hba.conf"
systemctl restart postgresql

echo "== 4. Usuario y base con mínimo privilegio (no es superusuario)"
PASS=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-28)
sudo -u postgres psql -v ON_ERROR_STOP=1 -q <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'atalaya') THEN
    CREATE ROLE atalaya LOGIN PASSWORD '$PASS' NOSUPERUSER NOCREATEDB NOCREATEROLE;
  ELSE
    ALTER ROLE atalaya PASSWORD '$PASS';
  END IF;
END \$\$;
SQL
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='atalaya'" | grep -q 1 || sudo -u postgres createdb -O atalaya atalaya
sudo -u postgres psql -q -d atalaya -c "REVOKE ALL ON DATABASE atalaya FROM PUBLIC; REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT ALL ON SCHEMA public TO atalaya;"

echo "== 5. Verificación"
ss -ltnp | grep 5432 || true
sudo -u postgres psql -tAc "SELECT rolname, rolsuper FROM pg_roles WHERE rolname='atalaya'"

echo
echo "Agrega esta línea al .env del backend (y NO la subas a GitHub):"
echo "DATABASE_URL=postgres://atalaya:${PASS}@127.0.0.1:5432/atalaya"
echo "Después: npm ci (con internet) · npm run db:migrate · sudo systemctl restart atalaya-backend"
