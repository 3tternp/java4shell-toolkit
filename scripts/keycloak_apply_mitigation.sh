#!/bin/bash
# =============================================================================
# keycloak_apply_mitigation.sh
# Vairav Technology CSOC - temporary CVE-2026-114938 (Java4Shell) mitigation
# for Keycloak running as a systemd service.
# Adds -XX:-UseBASE64Intrinsics through JAVA_OPTS_APPEND using a systemd
# drop-in, restarts Keycloak and verifies the flag on the new process.
# Usage:  sudo bash keycloak_apply_mitigation.sh [systemd-service-name]
# Rollback: sudo bash keycloak_apply_mitigation.sh --rollback [service-name]
# NOTE: restarting Keycloak interrupts logins briefly - use a change window.
# =============================================================================

FLAG="-XX:-UseBASE64Intrinsics"

if [ "$1" = "--rollback" ]; then
  ROLLBACK=1; SERVICE="${2:-keycloak}"
else
  ROLLBACK=0; SERVICE="${1:-keycloak}"
fi
DROPIN_DIR="/etc/systemd/system/${SERVICE}.service.d"
DROPIN="${DROPIN_DIR}/java4shell-mitigation.conf"

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Run as root (sudo)."; exit 1
fi
if ! systemctl cat "$SERVICE" >/dev/null 2>&1; then
  echo "[!] systemd service '$SERVICE' not found. Pass the correct name as an argument."
  exit 1
fi

if [ "$ROLLBACK" -eq 1 ]; then
  if [ -f "$DROPIN" ]; then
    rm -f "$DROPIN"
    systemctl daemon-reload
    echo "[+] Drop-in removed. Restarting $SERVICE ..."
    systemctl restart "$SERVICE" && echo "[+] Rollback complete."
  else
    echo "[i] No mitigation drop-in found at $DROPIN - nothing to roll back."
  fi
  exit 0
fi

# Detect an existing JAVA_OPTS_APPEND so it is preserved, not overwritten
EXISTING=$(systemctl show -p Environment --value "$SERVICE" | tr ' ' '\n' | grep '^JAVA_OPTS_APPEND=' | cut -d= -f2-)
for f in /etc/default/"$SERVICE" /opt/keycloak/conf/keycloak.conf; do
  [ -f "$f" ] && grep -q 'JAVA_OPTS_APPEND' "$f" && echo "[!] JAVA_OPTS_APPEND also set in $f - review manually so values do not conflict."
done

if echo "$EXISTING" | grep -q -- "$FLAG"; then
  echo "[i] $FLAG already present in $SERVICE environment."
else
  NEWVAL=$(echo "$EXISTING $FLAG" | sed 's/^ *//')
  mkdir -p "$DROPIN_DIR"
  cat > "$DROPIN" <<EOF
# Temporary mitigation for CVE-2026-114938 (Java4Shell) - added $(date '+%F %T')
# Remove after Java is patched:  sudo bash keycloak_apply_mitigation.sh --rollback $SERVICE
[Service]
Environment="JAVA_OPTS_APPEND=${NEWVAL}"
EOF
  echo "[+] Drop-in written: $DROPIN"
  [ -n "$EXISTING" ] && echo "[i] Preserved existing JAVA_OPTS_APPEND: $EXISTING"
  systemctl daemon-reload
fi

echo "[+] Restarting $SERVICE ..."
systemctl restart "$SERVICE" || { echo "[!] Restart failed - check: journalctl -u $SERVICE -n 50"; exit 1; }

# Wait for the new Java process
for i in $(seq 1 30); do
  PID=$(systemctl show -p MainPID --value "$SERVICE")
  [ -n "$PID" ] && [ "$PID" != "0" ] && [ "$(basename "$(readlink -f /proc/$PID/exe 2>/dev/null)")" = "java" ] && break
  PID=$(pgrep -f 'quarkus-run.jar' | head -1)
  [ -n "$PID" ] && break
  sleep 2
done

if [ -z "$PID" ]; then
  echo "[!] Could not find the restarted Keycloak Java process. Check: systemctl status $SERVICE"
  exit 1
fi

echo "[+] New Keycloak PID: $PID"
if (tr '\0' ' ' < /proc/$PID/cmdline; tr '\0' '\n' < /proc/$PID/environ) | grep -q -- "$FLAG"; then
  echo "[+] VERIFIED: $FLAG is active on the running Keycloak process."
else
  echo "[!] Flag NOT found on the running process. Your unit may launch Java in a way"
  echo "    that ignores JAVA_OPTS_APPEND - add $FLAG to the java command line manually."
  exit 1
fi
echo "[i] Remember to roll back after patching Java:  sudo bash $0 --rollback $SERVICE"
