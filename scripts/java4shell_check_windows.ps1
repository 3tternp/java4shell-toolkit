<#
=============================================================================
 java4shell_check_windows.ps1
 Vairav Technology CSOC - CVE-2026-114938 (Java4Shell) exposure check
 Checks CPU model, every running Java process, its version, and whether the
 temporary mitigation flag is active. Read-only.
 Usage (elevated PowerShell):
   powershell -ExecutionPolicy Bypass -File .\java4shell_check_windows.ps1
=============================================================================
#>

Write-Host "=================================================================="
Write-Host " Java4Shell (CVE-2026-114938) exposure check - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "=================================================================="

Write-Host "`n=== 1. CPU ==="
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
Write-Host "Model: $($cpu.Name)"
Write-Host "Affected families: Intel Xeon Ice Lake / Sapphire Rapids / Emerald Rapids / Granite Rapids (3rd-6th Gen Xeon Scalable), AMD Zen 4 or newer (EPYC 9004+, Ryzen 7000+)."

Write-Host "`n=== 2. Running Java processes ==="
$procs = Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^javaw?\.exe$' }
if (-not $procs) { Write-Host "No running Java processes found." }

foreach ($p in $procs) {
    $exe = $p.ExecutablePath
    $ver = if ($exe) { (& $exe -version 2>&1 | ForEach-Object { "$_" } | Where-Object { $_ -notmatch '^Picked up' } | Select-Object -First 1) } else { "unknown (no path)" }
    $cmd = [string]$p.CommandLine
    $envOpts = @($env:JAVA_TOOL_OPTIONS, $env:JDK_JAVA_OPTIONS) -join ' '
    $mit = if (($cmd + ' ' + $envOpts) -match '-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2]') { 'MITIGATED (flag on command line / env)' } else { 'NOT MITIGATED (check service-specific JVM options too)' }

    $avx = 'n/a'
    if ($exe) {
        $pf = & $exe -XX:+PrintFlagsFinal -version 2>$null | Select-String -Pattern '\bUseAVX\b'
        if ($pf) { $avx = ($pf.Line -split '\s+' | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1) }
    }

    Write-Host "------------------------------------------------------------------"
    Write-Host "PID      : $($p.ProcessId)"
    Write-Host "Java     : $exe"
    Write-Host "Version  : $ver"
    Write-Host "UseAVX   : $avx  (3 = JVM uses AVX-512 on this CPU; 2 or less = vulnerable path not used)"
    Write-Host "Flag     : $mit"
    Write-Host "Command  : $($cmd.Substring(0, [Math]::Min(160, $cmd.Length)))"
}

Write-Host "`n=== 3. JVM crash files since 1 Sep 2026 (possible probing) ==="
$roots = @("$env:SystemDrive\") | Where-Object { Test-Path $_ }
Get-ChildItem -Path $roots -Filter 'hs_err_pid*.log' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -ge [datetime]'2026-09-01' } |
    Select-Object FullName, LastWriteTime | Format-Table -AutoSize

Write-Host "`n=================================================================="
Write-Host " Affected Java: 17.0.6+ (below 17.0.21.1), 21 (below 21.0.13.1), 25 (below 25.0.5.1),"
Write-Host " 27 (below 27.0.1.1), 8u511b33-perf. Java 8/11 standard not affected."
Write-Host " Vendor build numbers differ - see guide Section 6."
Write-Host "=================================================================="
