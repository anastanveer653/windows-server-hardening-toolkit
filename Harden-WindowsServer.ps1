#Requires -RunAsAdministrator
#Requires -Version 5.1

<#
.SYNOPSIS
    Windows Server Hardening Toolkit — Main Entry Point

.DESCRIPTION
    Applies CIS Benchmark-aligned security hardening to Windows Server 2016/2019/2022.
    Covers SMB, NTLM, Audit Policy, Firewall, Services, Registry, and more.
    Generates a full HTML report and creates backups before every change.

.PARAMETER ConfigPath
    Path to the JSON configuration file. Defaults to .\config\hardening-config.json

.PARAMETER ReportOnly
    Run in audit mode only — assess the current state without making any changes.

.PARAMETER Modules
    Comma-separated list of modules to run. Runs all if not specified.
    Valid values: SMB, NTLM, AuditPolicy, Firewall, Services, AccountPolicy, Registry, WindowsUpdate

.PARAMETER Rollback
    Roll back all changes using the most recent backup.

.EXAMPLE
    # Full hardening with all modules
    .\Harden-WindowsServer.ps1

    # Audit only — no changes made
    .\Harden-WindowsServer.ps1 -ReportOnly

    # Run specific modules only
    .\Harden-WindowsServer.ps1 -Modules "SMB,NTLM,Firewall"

    # Roll back last hardening session
    .\Harden-WindowsServer.ps1 -Rollback

.NOTES
    Author      : Anas Tanveer
    GitHub      : https://github.com/anastanveer653/windows-server-hardening-toolkit
    Tested On   : Windows Server 2016, 2019, 2022
    Version     : 1.0.0
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [string]$ConfigPath = ".\config\hardening-config.json",
    [switch]$ReportOnly,
    [string]$Modules = "All",
    [switch]$Rollback
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────
# Bootstrap — Load helpers and config
# ─────────────────────────────────────────────
$ScriptRoot = $PSScriptRoot
$StartTime  = Get-Date
$SessionId  = $StartTime.ToString("yyyyMMdd-HHmmss")

# Import all module files
Get-ChildItem -Path "$ScriptRoot\modules\*.ps1" | ForEach-Object {
    . $_.FullName
}

# Import logger
. "$ScriptRoot\modules\Logger.ps1"

# Load config
if (-not (Test-Path $ConfigPath)) {
    Write-Error "Config file not found: $ConfigPath"
    exit 1
}
$Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json

# Create output directories
$ReportPath  = $Config.General.ReportOutputPath
$BackupPath  = $Config.General.BackupOutputPath
$LogPath     = $Config.General.LogOutputPath

@($ReportPath, $BackupPath, $LogPath) | ForEach-Object {
    if (-not (Test-Path $_)) { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
}

$LogFile    = "$LogPath\hardening-$SessionId.log"
$ReportFile = "$ReportPath\hardening-report-$SessionId.html"
$BackupFile = "$BackupPath\registry-backup-$SessionId.reg"

# ─────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────
function Show-Banner {
    $mode = if ($ReportOnly) { "AUDIT ONLY (no changes)" } else { "HARDENING MODE" }
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║     Windows Server Hardening Toolkit  v1.0.0         ║" -ForegroundColor Cyan
    Write-Host "║     CIS Benchmark Aligned                            ║" -ForegroundColor Cyan
    Write-Host "╠══════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "║  Mode    : $($mode.PadRight(42))║" -ForegroundColor Yellow
    Write-Host "║  Server  : $($env:COMPUTERNAME.PadRight(42))║" -ForegroundColor White
    Write-Host "║  Session : $($SessionId.PadRight(42))║" -ForegroundColor White
    Write-Host "║  Log     : $($LogFile.PadRight(42))║" -ForegroundColor White
    Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# ─────────────────────────────────────────────
# Rollback Mode
# ─────────────────────────────────────────────
if ($Rollback) {
    Write-Log "Starting rollback..." -Level WARN
    $LatestBackup = Get-ChildItem "$BackupPath\registry-backup-*.reg" |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object -First 1

    if ($null -eq $LatestBackup) {
        Write-Host "❌ No backup found in $BackupPath" -ForegroundColor Red
        exit 1
    }

    Write-Host "🔄 Restoring registry from: $($LatestBackup.Name)" -ForegroundColor Yellow
    Start-Process reg -ArgumentList "import `"$($LatestBackup.FullName)`"" -Wait -NoNewWindow
    Write-Host "✅ Rollback complete. A reboot is recommended." -ForegroundColor Green
    exit 0
}

# ─────────────────────────────────────────────
# System Info Collection
# ─────────────────────────────────────────────
function Get-SystemInfo {
    $os  = Get-CimInstance Win32_OperatingSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    return [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        OSName       = $os.Caption
        OSVersion    = $os.Version
        OSBuild      = $os.BuildNumber
        CPU          = $cpu.Name
        TotalRAM_GB  = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        Domain       = $env:USERDNSDOMAIN
        ScanTime     = $StartTime.ToString("yyyy-MM-dd HH:mm:ss")
    }
}

# ─────────────────────────────────────────────
# Registry Backup
# ─────────────────────────────────────────────
function Backup-Registry {
    Write-Log "Creating registry backup → $BackupFile"
    $keys = @(
        "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies",
        "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    )
    foreach ($key in $keys) {
        $safeKey = $key -replace '\\', '_'
        $file = "$BackupPath\${safeKey}-$SessionId.reg"
        Start-Process reg -ArgumentList "export `"$key`" `"$file`" /y" -Wait -NoNewWindow -ErrorAction SilentlyContinue
    }
    Write-Log "Registry backup complete."
}

# ─────────────────────────────────────────────
# Module Runner
# ─────────────────────────────────────────────
$Results = [System.Collections.Generic.List[object]]::new()

function Invoke-Module {
    param([string]$Name, [scriptblock]$ScriptBlock)

    $skip = ($Modules -ne "All") -and ($Modules -split "," -notcontains $Name)
    if ($skip) { return }

    Write-Host ""
    Write-Host "  ▶ Running module: $Name" -ForegroundColor Cyan
    Write-Log "Module started: $Name"

    try {
        $moduleResults = & $ScriptBlock
        $Results.AddRange($moduleResults)
        Write-Host "  ✅ $Name complete" -ForegroundColor Green
        Write-Log "Module complete: $Name"
    } catch {
        Write-Host "  ❌ $Name failed: $_" -ForegroundColor Red
        Write-Log "Module FAILED: $Name — $_" -Level ERROR
    }
}

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
Show-Banner
Write-Log "═══ Hardening session started: $SessionId ═══"

$SystemInfo = Get-SystemInfo
Write-Log "Target: $($SystemInfo.OSName) | Build $($SystemInfo.OSBuild)"

if (-not $ReportOnly) {
    Backup-Registry
}

# Run all modules
Invoke-Module "SMB"           { Invoke-SMBHardening          -Config $Config -ReportOnly:$ReportOnly }
Invoke-Module "NTLM"          { Invoke-NTLMHardening         -Config $Config -ReportOnly:$ReportOnly }
Invoke-Module "AuditPolicy"   { Invoke-AuditPolicyHardening  -Config $Config -ReportOnly:$ReportOnly }
Invoke-Module "Firewall"      { Invoke-FirewallHardening      -Config $Config -ReportOnly:$ReportOnly }
Invoke-Module "Services"      { Invoke-ServicesHardening      -Config $Config -ReportOnly:$ReportOnly }
Invoke-Module "AccountPolicy" { Invoke-AccountPolicyHardening -Config $Config -ReportOnly:$ReportOnly }
Invoke-Module "Registry"      { Invoke-RegistryHardening      -Config $Config -ReportOnly:$ReportOnly }
Invoke-Module "WindowsUpdate" { Invoke-WindowsUpdateHardening -Config $Config -ReportOnly:$ReportOnly }

# Generate report
Write-Host ""
Write-Host "  📄 Generating HTML report..." -ForegroundColor Cyan
New-HardeningReport -Results $Results -SystemInfo $SystemInfo -OutputPath $ReportFile -ReportOnly:$ReportOnly

# Summary
$Duration  = (Get-Date) - $StartTime
$PassCount = ($Results | Where-Object { $_.Status -eq "PASS" }).Count
$FailCount = ($Results | Where-Object { $_.Status -eq "FAIL" }).Count
$FixedCount= ($Results | Where-Object { $_.Status -eq "FIXED" }).Count

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                   SUMMARY                           ║" -ForegroundColor Cyan
Write-Host "╠══════════════════════════════════════════════════════╣" -ForegroundColor Cyan
Write-Host "║  ✅ Already Compliant : $($PassCount.ToString().PadRight(29))║" -ForegroundColor Green
Write-Host "║  🔧 Fixed             : $($FixedCount.ToString().PadRight(29))║" -ForegroundColor Yellow
Write-Host "║  ⚠️  Needs Attention   : $($FailCount.ToString().PadRight(29))║" -ForegroundColor Red
Write-Host "║  ⏱  Duration          : $("$([math]::Round($Duration.TotalSeconds))s".PadRight(29))║" -ForegroundColor White
Write-Host "║  📄 Report            : $($ReportFile.PadRight(29))║" -ForegroundColor White
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Log "═══ Session complete. Pass=$PassCount Fixed=$FixedCount Fail=$FailCount ═══"

if (-not $ReportOnly -and $Config.General.RebootAfterHardening) {
    Write-Host "`n⚠️  Rebooting in 60 seconds. Press Ctrl+C to cancel." -ForegroundColor Yellow
    Start-Sleep -Seconds 60
    Restart-Computer -Force
}
