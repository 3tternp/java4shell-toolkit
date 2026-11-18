# 🧬 Java4Shell Toolkit CVE-2026-114938

> **Vairav Technology Security Pvt. Ltd. · Cyber Security Operations Centre (CSOC)**
> Guide **VTS-TG-2026-1118-JAVA4SHELL** · 🏷️ **TLP:CLEAR** · 18 November 2026

Scripts to **check** whether servers are exposed to Java4Shell (CVE-2026-114938), **mitigate** Keycloak on Debian/Ubuntu, and **roll back** after patching.

---

## 🧭 Contents

- [🔬 What makes a server exposed](#-what-makes-a-server-exposed)
- [🗂️ Package contents](#️-package-contents)
- [🪪 Requirements](#-requirements)
- [🐧 Script 1 Linux check](#-script-1--java4shell_check_linuxsh)
- [🗝️ Script 2 Keycloak check](#️-script-2--keycloak_java4shell_checksh)
- [🧯 Script 3 Keycloak mitigation and rollback](#-script-3--keycloak_apply_mitigationsh)
- [🪟 Script 4 Windows check](#-script-4--java4shell_check_windowsps1)
- [🧮 Reading the results](#-reading-the-results)
- [📦 Fixed versions](#-fixed-versions)
- [🐳 Keycloak in Docker](#-keycloak-in-docker)
- [🩹 Patch and roll back](#-patch-and-roll-back)
- [🪛 Troubleshooting](#-troubleshooting)
- [🧷 Verify file integrity](#-verify-file-integrity)
- [🧪 Testing status](#-testing-status)

---

## 🔬 What makes a server exposed

A server is exposed **only when all three conditions are true**:

| # | Condition | Detail |
|---|---|---|
| 1️⃣ | 🖥️ **CPU** | x86-64 with `avx512f`, `avx512bw`, `avx512vbmi`, `bmi2` Intel Xeon Ice Lake or newer, AMD Zen 4 or newer. ARM64 is **not** affected. |
| 2️⃣ | ☕ **Java build** | A *running* JVM on 17.0.6+ (17 line), or unpatched 21 / 25 / 27, or 8u511b33-perf |
| 3️⃣ | 🚩 **No mitigation** | The JVM does **not** have `-XX:-UseBASE64Intrinsics` active |

> 🛑 **Never test by sending malformed Base64 to a production application** a failed trigger crashes the JVM.

---

## 🗂️ Package contents

```
java4shell-toolkit/
├── 📘 README.md                                   ← this file
├── 📗 Java4Shell_Check_and_Mitigation_Guide.docx  ← full runbook
├── 🧷 SHA256SUMS.txt                              ← script checksums
└── 📁 scripts/
    ├── 🐧 java4shell_check_linux.sh               ← any Linux host
    ├── 🗝️ keycloak_java4shell_check.sh            ← Keycloak on Debian/Ubuntu
    ├── 🧯 keycloak_apply_mitigation.sh            ← apply / roll back flag
    └── 🪟 java4shell_check_windows.ps1            ← Windows hosts
```

| Script | Platform | 👁️ Read-only | 🔄 Restarts services |
|---|---|:---:|:---:|
| 🐧 `java4shell_check_linux.sh` | Linux (any distro) | ✔️ | ✖️ |
| 🗝️ `keycloak_java4shell_check.sh` | Debian / Ubuntu | ✔️ | ✖️ |
| 🧯 `keycloak_apply_mitigation.sh` | Debian / Ubuntu (systemd) | ✖️ | ✔️ **Keycloak** |
| 🪟 `java4shell_check_windows.ps1` | Windows / Windows Server | ✔️ | ✖️ |

---

## 🪪 Requirements

| Platform | Needs |
|---|---|
| 🐧 Linux | `bash`, `root` (sudo), standard tools (`grep`, `pgrep`, `ps`, `find`). Optional: `dpkg`/`rpm`, `journalctl`, `ss`/`netstat`, `jcmd` (full JDK) |
| 🗝️ Keycloak mitigation | `systemd`-managed Keycloak service; a change window |
| 🪟 Windows | PowerShell 5.1+ run **as Administrator** |

Unpack on the target server:

```bash
unzip java4shell-toolkit.zip
cd java4shell-toolkit/scripts
chmod +x *.sh
```

---

## 🐧 Script 1 `java4shell_check_linux.sh`

Checks the **CPU** and **every running JVM** on any Linux host.

**Usage**

```bash
sudo ./java4shell_check_linux.sh
sudo ./java4shell_check_linux.sh | tee java4shell_$(hostname).txt   # save report
```

**What it reports**

| Section | Output |
|---|---|
| 🖥️ 1. CPU | Model, architecture, `AVX-512 VBMI: YES / NO` |
| ☕ 2. Running JVMs | PID, user, Java path, version, OS package, `MITIGATED / NOT MITIGATED`, command line |
| 💥 3. Crash files | `hs_err_pid*.log` written since 1 Sep 2026 (possible probing) |
| 🧾 Interpretation | Affected version ranges and verdict hint |

**Sample output**

```
=== 1. CPU ===
model name : Intel(R) Xeon(R) Processor @ 2.10GHz
>> AVX-512 VBMI: YES - affected hardware

=== 2. Running JVMs ===
PID      : 404 (user: keycloak)
Java     : /usr/lib/jvm/java-21-openjdk-amd64/bin/java
Version  : openjdk version "21.0.12.1" 2026-08-18
Package  : openjdk-21-jre-headless
Flag     : NOT MITIGATED
```

---

## 🗝️ Script 2 `keycloak_java4shell_check.sh`

Keycloak-focused check for **Debian / Ubuntu**.

**Usage**

```bash
sudo ./keycloak_java4shell_check.sh              # systemd service "keycloak"
sudo ./keycloak_java4shell_check.sh my-kc        # custom service name
```

It finds Keycloak through the systemd unit's `MainPID`, falling back to a process running `quarkus-run.jar`.

**What it reports**

| Section | Output |
|---|---|
| 🖥️ 1. CPU | `AVX-512 VBMI: YES / NO` |
| ☕ 2. Keycloak process | PID, owning user, Java path and version |
| 📦 3. Debian package | Owning `openjdk-*` package, installed vs candidate version, Debian tracker link |
| 🚩 4. Mitigation flag | `MITIGATED / NOT MITIGATED` on the running process (+ `jcmd VM.flags` if JDK present) |
| 💥 5. Probing / crashes | `hs_err_pid` files, Base64 decode errors and restart count from the journal |
| 🌐 6. Exposure | Keycloak's listening sockets (`ss`, falls back to `netstat`) |

---

## 🧯 Script 3 `keycloak_apply_mitigation.sh`

Applies the temporary JVM flag to Keycloak and verifies it — or removes it after patching.

> 🔄 **Restarts Keycloak** logins are briefly interrupted. Run in a change window, on a test/staging instance first.

**Usage**

```bash
# 🧯 Apply
sudo ./keycloak_apply_mitigation.sh                  # service "keycloak"
sudo ./keycloak_apply_mitigation.sh my-kc            # custom service name

# ↩️ Roll back (after Java is patched)
sudo ./keycloak_apply_mitigation.sh --rollback
sudo ./keycloak_apply_mitigation.sh --rollback my-kc
```

**What it does**

1. 🔎 Reads any existing `JAVA_OPTS_APPEND` and **preserves it**, appending `-XX:-UseBASE64Intrinsics`
2. 📝 Writes `/etc/systemd/system/<service>.service.d/java4shell-mitigation.conf` and reloads systemd
3. 🔄 Restarts Keycloak and waits for the new Java process
4. 🔐 **Verifies** the flag is present on the running process
5. 🔔 Warns if `JAVA_OPTS_APPEND` is also set in `/etc/default/<service>` or `keycloak.conf`

**Expected output**

```
[+] Drop-in written: /etc/systemd/system/keycloak.service.d/java4shell-mitigation.conf
[+] Restarting keycloak ...
[+] New Keycloak PID: 21873
[+] VERIFIED: -XX:-UseBASE64Intrinsics is active on the running Keycloak process.
```

**Manual alternative**

```bash
sudo systemctl edit keycloak
# add:
[Service]
Environment="JAVA_OPTS_APPEND=-XX:-UseBASE64Intrinsics"

sudo systemctl restart keycloak
sudo ./keycloak_java4shell_check.sh        # section 4 → MITIGATED
```

> 🚫 Do **not** use `-XX:DisableIntrinsic=_base64_decodeBlock` alone — Java will not start.
> 🔀 `-XX:UseAVX=2` also works but is **x86-64 only** (ARM64 Java will not start) and costs more performance.

---

## 🪟 Script 4 `java4shell_check_windows.ps1`

Checks the **CPU model** and **every running Java process** on Windows.

**Usage** (elevated PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File .\java4shell_check_windows.ps1
powershell -ExecutionPolicy Bypass -File .\java4shell_check_windows.ps1 | Tee-Object java4shell_$env:COMPUTERNAME.txt
```

**What it reports**

| Section | Output |
|---|---|
| 🖥️ 1. CPU | Model name + affected CPU families |
| ☕ 2. Java processes | PID, path, version, `UseAVX` value, flag status, command line |
| 💥 3. Crash files | `hs_err_pid*.log` since 1 Sep 2026 on the system drive |

> 🧩 **`UseAVX = 3`** → the JVM uses AVX-512 on this CPU. **`2` or less** → the vulnerable path is not used.
> Windows services (Tomcat, Jenkins, etc.) often keep JVM options in the service wrapper — confirm "NOT MITIGATED" there.

---

## 🧮 Reading the results

| 🖥️ CPU | ☕ Java version | 🚩 Flag | Verdict |
|---|---|---|---|
| NO | Any | Any | 🟢 Not exploitable now patch on normal schedule |
| YES | 8 / 11 / 17.0.0–17.0.5 | Any | 🟢 Not affected |
| YES | Fixed build | Any | 🟢 Patched remove flag if set |
| YES | Affected build | MITIGATED | 🟡 Protected patch when fix is available |
| YES | Affected build | NOT MITIGATED | 🔴 **VULNERABLE mitigate now** |

> ☁️ A VM resize or migration can move a workload onto affected hardware. Use the CPU result to prioritise, not to close findings.

---

## 📦 Fixed versions

| Distribution | Fixed version |
|---|---|
| Oracle Java SE 17 / 21 / 25 / 27 | 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1 |
| Java SE 8 Performance Pack | 8u513-perf |
| Amazon Corretto 17 / 21 / 25 / 27 | 17.0.21.1.2 / 21.0.13.1.2 / 25.0.5.1.2 / 27.0.1.1.4 |
| Azul Zulu 17 / 21 / 25 / 27 | 17.70.201 / 21.54.201 / 25.38.201 / 27.30.201 |
| GraalVM JDK 17 / 21 / EE | 17.0.21.1 / 21.0.13.1 / 21.3.20.1 |
| Debian `openjdk-17` / `openjdk-21` | 🔗 https://security-tracker.debian.org/tracker/CVE-2026-114938 |
| Red Hat · Temurin · Microsoft · Liberica | ⏳ Not released at time of writing — use the flag |

> 📅 Fix status changes daily confirm with vendor advisories before closing findings.

---

## 🐳 Keycloak in Docker

The official Keycloak image uses **Red Hat OpenJDK** (no fix yet). Add the flag and **recreate** the container:

```bash
docker run ... -e JAVA_OPTS_APPEND="-XX:-UseBASE64Intrinsics" quay.io/keycloak/keycloak:<tag> start
```

```yaml
# docker-compose.yml
environment:
  JAVA_OPTS_APPEND: "-XX:-UseBASE64Intrinsics"
```

```bash
# 🔐 verify from the host
docker exec <container> sh -c 'tr "\0" "\n" < /proc/1/environ | grep JAVA_OPTS_APPEND'
```

---

## 🩹 Patch and roll back

```bash
# 1. 📥 Install the fixed Java once Debian publishes it
sudo apt update && apt list --upgradable 2>/dev/null | grep -i openjdk
sudo apt install --only-upgrade openjdk-17-jre-headless     # or openjdk-21-jre-headless

# 2. ↩️ Remove the temporary flag (restarts Keycloak)
sudo ./keycloak_apply_mitigation.sh --rollback

# 3. 🔁 Confirm the patched version is running
sudo ./keycloak_java4shell_check.sh
```

---

## 🪛 Troubleshooting

| Symptom | Fix |
|---|---|
| 🔍 `Keycloak Java process not found` | Pass the correct service name; for Docker run `docker exec <container> java -version` |
| 🔌 `jcmd ... could not attach` | `jcmd` ships only with the full JDK; the `/proc` check in section 4 is sufficient |
| 🚩 Flag NOT found after mitigation | Unit does not start Java through `kc.sh` — add the flag to the `ExecStart` java command |
| 💢 Restart failed | `journalctl -u keycloak -n 50`, then `--rollback` |
| 🔢 Vendor build number in version | Compare with the [fixed versions](#-fixed-versions) table / vendor notes |
| 📢 `Picked up JAVA_TOOL_OPTIONS` noise | Already filtered by the scripts; harmless |

---

## 🧷 Verify file integrity

```bash
cd java4shell-toolkit/scripts
sha256sum -c ../SHA256SUMS.txt
```

---

## 🧪 Testing status

| Script | Status |
|---|---|
| 🐧 `java4shell_check_linux.sh` | ✔️ Tested on an AVX-512 VBMI host against OpenJDK 21 processes with and without the flag |
| 🗝️ `keycloak_java4shell_check.sh` | ✔️ Tested as above (process fallback path, Debian package lookup) |
| 🧯 `keycloak_apply_mitigation.sh` | 🔶 Syntax-checked only — **test on non-production systemd host first** |
| 🪟 `java4shell_check_windows.ps1` | 🔶 Reviewed only — **test on a non-production Windows host first** |

---

<sub>🛡️ Vairav Technology Security Pvt. Ltd. · CSOC · Kathmandu, Nepal · For assistance with assessment, patching or detection, contact your Vairav CSOC point of contact.</sub>
