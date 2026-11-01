#!/usr/bin/env bash
# Guarda en ~/evidencias/ la salida de los comandos que pide la práctica 2.4 (ec2-backend).
OUT=~/evidencias/snort-$(date +%Y%m%d-%H%M%S).txt; mkdir -p ~/evidencias
IFACE=${1:-eth0}
run() { echo -e "\n===== \$ $* =====" | tee -a "$OUT"; eval "$@" 2>&1 | tee -a "$OUT"; }
run cat /etc/os-release
run ip -br address
run ip route
run snort -V
run ls -la /etc/snort
run ls -la /etc/snort/rules
run ls -la /var/log/snort
run "grep -nE 'ipvar HOME_NET|ipvar EXTERNAL_NET|var RULE_PATH|local.rules|alert_fast|config umask' /etc/snort/snort.conf"
run cat /etc/snort/snort.debian.conf
run cat /etc/snort/rules/local.rules
run sudo snort -T -c /etc/snort/snort.conf -i $IFACE \| tail -n 25
run sudo systemctl status snort --no-pager
run sudo journalctl -u snort -n 50 --no-pager
run "ps -ef | grep [s]nort"
run sudo tail -n 20 /var/log/snort/alert_fast.txt
echo -e "\nGuardado en $OUT"
