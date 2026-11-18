# Java4Shell (CVE-2026-114938) Toolkit — Vairav Technology CSOC

Companion to advisory **VTS-SA-2026-1118-JAVA4SHELL**. TLP:CLEAR.
Full instructions: `Java4Shell_Check_and_Mitigation_Guide.docx`. Advisory: `VTS-SA-2026-1118-JAVA4SHELL.docx`.

A server is exposed only if **all three** are true:
1. x86-64 CPU with AVX-512 VBMI (Intel Ice Lake+ / AMD Zen 4+)
2. A running JVM on an affected build (17.0.6+, unpatched 21 / 25 / 27)
3. The JVM does not have `-XX:-UseBASE64Intrinsics` active

## Scripts

| Script | Use | Changes system? |
|---|---|---|
| `scripts/java4shell_check_linux.sh` | Any Linux host — CPU + all running JVMs | No |
| `scripts/keycloak_java4shell_check.sh [service]` | Keycloak on Debian/Ubuntu | No |
| `scripts/keycloak_apply_mitigation.sh [service]` | Add flag via systemd drop-in, restart, verify | **Yes — restarts Keycloak** |
| `scripts/keycloak_apply_mitigation.sh --rollback [service]` | Remove flag after patching | **Yes — restarts Keycloak** |
| `scripts/java4shell_check_windows.ps1` | Windows hosts | No |

## Quick start (Keycloak on Debian)

```bash
cd scripts && chmod +x *.sh
sudo ./keycloak_java4shell_check.sh          # 1. check
sudo ./keycloak_apply_mitigation.sh          # 2. mitigate if VULNERABLE (change window)
# ... after Debian ships fixed openjdk:
sudo apt install --only-upgrade openjdk-21-jre-headless
sudo ./keycloak_apply_mitigation.sh --rollback
```

**Never test by sending malformed Base64 to production — it crashes the JVM.**
