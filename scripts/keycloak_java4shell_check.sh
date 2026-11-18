#!/bin/bash
# =============================================================================
# keycloak_java4shell_check.sh
# Vairav Technology CSOC - CVE-2026-114938 (Java4Shell) check for Keycloak
# on Debian / Ubuntu.
# Usage:  sudo bash keycloak_java4shell_check.sh [systemd-service-name]
#         (default service name: keycloak)
# Read-only: makes no changes to the system.
# =============================================================================

SERVICE="${1:-keycloak}"

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Run as root (sudo)."
  exit 1
fi

echo "=================================================================="
echo " Keycloak Java4Shell check - $(hostname) - $(date '+%F %T')"
echo "=================================================================="

echo
echo "=== 1. CPU (all 4 flags = affected hardware) ==="
grep -m1 'model name' /proc/cpuinfo
n=$(grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -cE '^(avx512f|avx512bw|avx512vbmi|bmi2)$')
if [ "$(uname -m)" = "x86_64" ] && [ "$n" -eq 4 ]; then
  echo ">> AVX-512 VBMI: YES - affected hardware"
else
  echo ">> AVX-512 VBMI: NO ($n/4 flags, arch $(uname -m)) - not exploitable on this CPU"
fi

echo
echo "=== 2. Keycloak process and its Java ==="
PID=$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null)
if [ -z "$PID" ] || [ "$PID" = "0" ] || [ "$(basename "$(readlink -f /proc/$PID/exe 2>/dev/null)")" != "java" ]; then
  PID=$(pgrep -f 'quarkus-run.jar|keycloak' | while read -r p; do
          [ "$(basename "$(readlink -f /proc/$p/exe 2>/dev/null)")" = "java" ] && echo "$p"; done | head -1)
fi
if [ -z "$PID" ]; then
  echo "[!] Keycloak Java process not found. Is it running? (service name: $SERVICE)"
  echo "    If Keycloak runs in Docker, run: docker exec <container> java -version"
  exit 1
fi
JAVA=$(readlink -f /proc/$PID/exe)
echo "PID   : $PID (user: $(ps -o user= -p "$PID"))"
echo "Java  : $JAVA"
"$JAVA" -version 2>&1 | grep -v "^Picked up" | head -2

echo
echo "=== 3. Debian package owning this Java ==="
if PKG=$(dpkg -S "$JAVA" 2>/dev/null | cut -d: -f1) && [ -n "$PKG" ]; then
  echo "Package: $PKG"
  apt-cache policy "$PKG" | head -3
  echo "Check fix status: https://security-tracker.debian.org/tracker/CVE-2026-114938"
else
  echo "Not a Debian package (manual install, e.g. Temurin/Zulu under /opt)."
  echo "Compare the version above with the vendor fix table in the guide (Section 6)."
fi

echo
echo "=== 4. Mitigation flag active on the running process? ==="
FLAGS=$( (tr '\0' ' ' < /proc/$PID/cmdline; echo; tr '\0' '\n' < /proc/$PID/environ | grep -E '^(JAVA_OPTS|JAVA_OPTS_APPEND|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS)=') )
if echo "$FLAGS" | grep -qE -- '-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2]'; then
  echo ">> MITIGATED (flag present on running process)"
else
  echo ">> NOT MITIGATED"
fi
if command -v jcmd >/dev/null 2>&1; then
  echo "jcmd VM.flags:"
  sudo -u "$(ps -o user= -p "$PID")" jcmd "$PID" VM.flags 2>/dev/null | tr ' ' '\n' | grep -E 'UseBASE64Intrinsics|UseAVX' || echo "  (jcmd could not attach)"
fi

echo
echo "=== 5. Signs of probing / crashes ==="
echo "JVM crash files since 1 Sep 2026:"
find / -xdev -name 'hs_err_pid*.log' -newermt 2026-09-01 2>/dev/null | head -20
echo -n "Base64 decode errors in $SERVICE journal since 1 Sep 2026: "
journalctl -u "$SERVICE" --since "2026-09-01" --no-pager 2>/dev/null | grep -cE 'IllegalArgumentException.*[Bb]ase64|Illegal base64'
echo -n "$SERVICE (re)starts in last 7 days: "
journalctl -u "$SERVICE" --since "7 days ago" --no-pager 2>/dev/null | grep -c 'Started'

echo
echo "=== 6. Network exposure (listening sockets of Keycloak) ==="
if command -v ss >/dev/null 2>&1; then ss -ltnp | grep "pid=$PID," || echo "(none found)"; else netstat -ltnp 2>/dev/null | grep " $PID/" || echo "(ss/netstat not available)"; fi

echo
echo "=================================================================="
echo " Next step if CPU = YES, Java affected and NOT MITIGATED:"
echo "   sudo bash keycloak_apply_mitigation.sh $SERVICE"
echo "=================================================================="
