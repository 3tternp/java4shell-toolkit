#!/bin/bash
# =============================================================================
# java4shell_check_linux.sh
# Vairav Technology CSOC - CVE-2026-114938 (Java4Shell) exposure check
# Checks: CPU AVX-512 VBMI support, every running JVM's version, and whether
# the temporary mitigation flag is active on each running process.
# Usage:  sudo bash java4shell_check_linux.sh
# Read-only: makes no changes to the system.
# =============================================================================

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Run as root (sudo) so all Java processes can be inspected."
  exit 1
fi

echo "=================================================================="
echo " Java4Shell (CVE-2026-114938) exposure check - $(hostname) - $(date '+%F %T')"
echo "=================================================================="

echo
echo "=== 1. CPU ==="
grep -m1 'model name' /proc/cpuinfo
ARCH=$(uname -m)
echo "Architecture: $ARCH"
CPU_AFFECTED=0
if [ "$ARCH" = "x86_64" ]; then
  n=$(grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -cE '^(avx512f|avx512bw|avx512vbmi|bmi2)$')
  if [ "$n" -eq 4 ]; then
    echo ">> AVX-512 VBMI: YES - affected hardware"
    CPU_AFFECTED=1
  else
    echo ">> AVX-512 VBMI: NO ($n/4 flags) - not exploitable on this CPU (re-check after VM resize/migration)"
  fi
else
  echo ">> Non-x86-64 architecture - not affected"
fi

echo
echo "=== 2. Running JVMs ==="
FOUND=0
for p in $(pgrep -f java); do
  exe=$(readlink -f /proc/$p/exe 2>/dev/null) || continue
  case "$(basename "$exe")" in java|javaw) ;; *) continue ;; esac
  FOUND=1
  ver=$("$exe" -version 2>&1 | grep -v "^Picked up" | head -1)
  user=$(ps -o user= -p "$p")
  opts=$( (tr '\0' ' ' < /proc/$p/cmdline; echo; tr '\0' '\n' < /proc/$p/environ 2>/dev/null | grep -E '^(JAVA_OPTS|JAVA_OPTS_APPEND|JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS)=') )
  if echo "$opts" | grep -qE -- '-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2]'; then
    mit="MITIGATED"
  else
    mit="NOT MITIGATED"
  fi
  pkg=$(dpkg -S "$exe" 2>/dev/null | cut -d: -f1)
  if [ -z "$pkg" ] && command -v rpm >/dev/null 2>&1; then
    pkg=$(rpm -qf "$exe" 2>/dev/null) || pkg=""
  fi
  echo "------------------------------------------------------------------"
  echo "PID      : $p (user: $user)"
  echo "Java     : $exe"
  echo "Version  : $ver"
  echo "Package  : ${pkg:-not from OS package manager (bundled / manual install)}"
  echo "Flag     : $mit"
  echo "Command  : $(tr '\0' ' ' < /proc/$p/cmdline | cut -c1-160)"
done
[ "$FOUND" -eq 0 ] && echo "No running Java processes found."

echo
echo "=== 3. JVM crash files since 1 Sep 2026 (possible probing) ==="
find / -xdev -name 'hs_err_pid*.log' -newermt 2026-09-01 2>/dev/null | head -20

echo
echo "=================================================================="
echo " Interpretation"
echo "  - Affected Java: 17.0.6+ (below 17.0.21.1), 21 (below 21.0.13.1),"
echo "    25 (below 25.0.5.1), 27 (below 27.0.1.1), 8u511b33-perf."
echo "    Vendor builds (Corretto/Zulu/Debian/Red Hat) use their own numbers -"
echo "    see the guide document, Section 6."
echo "  - Java 8/11 (standard) and 17.0.0-17.0.5 are not affected."
[ "$CPU_AFFECTED" -eq 1 ] && echo "  - CPU IS affected: any affected Java that is NOT MITIGATED needs action now." \
                          || echo "  - CPU not affected today: still patch Java (hardware can change)."
echo "=================================================================="
