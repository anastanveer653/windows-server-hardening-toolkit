<#
.SYNOPSIS
    Command line front end for the Windows Server Hardening Toolkit.

.DESCRIPTION
    Audits, hardens or rolls back a Windows Server using the WindowsServerHardening module.
    The default mode is a read-only audit. Every hardening run records the previous value of
    each changed setting so the session can be rolled back with -Mode Rollback.

    Exit codes (for schedulers, RMM tools and CI pipelines):
      0  All evaluated controls are compliant (or the rollback succeeded).
      1  Non-compliant controls or control errors were found (or a rollback step failed).
      2  The run itself failed (invalid parameters, missing rights, remote connection errors).

.PARAMETER Mode
    Audit (default, read-only), Harden (apply the profile) or Rollback (undo a hardening session).

.PARAMETER ProfileName
    Built-in profile: Auto (default), MemberServer, DomainController or WebServer.

.PARAMETER ProfilePath
    Path to a custom JSON profile.

.PARAMETER Category
    Limit the run to these categories, for example SMB, Authentication, Firewall.

.PARAMETER ControlId
    Limit the run to these control IDs. Wildcards are supported, for example 'SMB-*'.

.PARAMETER ExcludeControlId
    Skip these control IDs. Wildcards are supported.

.PARAMETER SessionId
    Rollback mode only: the hardening session to roll back. Defaults to the latest one.

.PARAMETER OutputPath
    Root folder for logs, reports and rollback data. Defaults to %ProgramData%\WindowsServerHardening.

.PARAMETER ReportFormat
    Report formats to write: Html, Json, Csv. Defaults to all three.

.PARAMETER ComputerName
    Audit mode only: remote servers to audit over PowerShell remoting.

.PARAMETER Credential
    Credential for remote audits.

.PARAMETER Force
    Harden or roll back without confirmation prompts.

.PARAMETER ReportOnly
    Deprecated (v1). Equivalent to -Mode Audit.

.PARAMETER Rollback
    Deprecated (v1). Equivalent to -Mode Rollback.

.PARAMETER Modules
    Deprecated (v1). Comma separated v1 module names, mapped to categories.

.EXAMPLE
    .\Harden-WindowsServer.ps1

    Audits the local server with the automatically selected profile and writes HTML, JSON and CSV reports.

.EXAMPLE
    .\Harden-WindowsServer.ps1 -Mode Harden -WhatIf

    Shows every change the hardening run would make, without changing anything.

.EXAMPLE
    .\Harden-WindowsServer.ps1 -Mode Harden -ProfileName WebServer -Category SMB, Authentication, Network -Force

    Hardens selected categories with the WebServer profile without prompting.

.EXAMPLE
    .\Harden-WindowsServer.ps1 -Mode Rollback

    Rolls back the most recent hardening session.

.EXAMPLE
    .\Harden-WindowsServer.ps1 -ComputerName SRV01, SRV02 -Credential (Get-Credential)

    Audits two remote servers and writes the reports locally.

.LINK
    https://github.com/anastanveer653/windows-server-hardening-toolkit
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive console front end; all data is also returned through reports and exit codes.')]
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', PositionalBinding = $false)]
param(
    [ValidateSet('Audit', 'Harden', 'Rollback')]
    [string]$Mode = 'Audit',

    [Alias('Profile')]
    [string]$ProfileName = 'Auto',

    [string]$ProfilePath,

    [string[]]$Category,

    [string[]]$ControlId,

    [string[]]$ExcludeControlId,

    [string]$SessionId,

    [string]$OutputPath,

    # Validated after comma splitting (see ConvertTo-ListArgument), so no ValidateSet here.
    [string[]]$ReportFormat = @('Html', 'Json', 'Csv'),

    [string[]]$ComputerName,

    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    [switch]$Force,

    # Deprecated v1 switches. (No DontShow: that attribute needs PowerShell 4.0 and would stop the
    # script from starting on Windows Server 2012 before the version check below can explain why.)
    [switch]$ReportOnly,

    [switch]$Rollback,

    [string]$Modules
)

# This file deliberately avoids #Requires and newer syntax so that it starts on any PowerShell
# version and can tell the user what to install instead of failing with a parser error.
if ($PSVersionTable.PSVersion -lt [version]'5.1') {
    Write-Host ''
    Write-Host "  Windows PowerShell 5.1 or later is required (this server has $($PSVersionTable.PSVersion))." -ForegroundColor Red
    Write-Host '  Install Windows Management Framework 5.1 (Windows Server 2012 / 2012 R2), restart, and run the script again:'
    Write-Host '  https://aka.ms/wmf51download'
    Write-Host ''
    exit 2
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-ListArgument {
    # "powershell.exe -File" (scheduled tasks, RMM tools, cmd.exe) passes "Json,Html" as one string
    # instead of an array. Splitting on commas makes lists work the same from every caller.
    param([string[]]$Value)
    return @($Value | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

$Category = ConvertTo-ListArgument -Value $Category
$ControlId = ConvertTo-ListArgument -Value $ControlId
$ExcludeControlId = ConvertTo-ListArgument -Value $ExcludeControlId
$ComputerName = ConvertTo-ListArgument -Value $ComputerName
$ReportFormat = ConvertTo-ListArgument -Value $ReportFormat
$invalidFormats = @($ReportFormat | Where-Object { @('Html', 'Json', 'Csv') -notcontains $_ })
if ($invalidFormats.Count -gt 0 -or $ReportFormat.Count -eq 0) {
    Write-Host ''
    Write-Host "  ERROR: Invalid -ReportFormat '$($invalidFormats -join ', ')'. Use one or more of: Html, Json, Csv (for example -ReportFormat Html,Json)." -ForegroundColor Red
    Write-Host ''
    exit 2
}

function Import-HardeningModule {
    $candidates = @(
        (Join-Path -Path $PSScriptRoot -ChildPath 'src\WindowsServerHardening\WindowsServerHardening.psd1')
        (Join-Path -Path $PSScriptRoot -ChildPath 'WindowsServerHardening\WindowsServerHardening.psd1')
    )
    $path = 'WindowsServerHardening'
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            $path = $candidate
            break
        }
    }
    try {
        return Import-Module -Name $path -Force -PassThru -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -match 'digitally signed|cannot be loaded|is not trusted|execution policy') {
            throw ("The module files are blocked by the execution policy, usually because they were downloaded. " +
                "Unblock them and allow scripts for this session, then try again:`n" +
                "    Get-ChildItem -Path '$PSScriptRoot' -Recurse | Unblock-File`n" +
                "    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force")
        }
        throw
    }
}

function Write-Rule {
    Write-Host ('  ' + ('-' * 66)) -ForegroundColor DarkGray
}

function Write-Banner {
    param([string]$Version, [string]$RunMode)

    $label = switch ($RunMode) {
        'Harden'   { 'HARDEN (changes will be applied)' }
        'Rollback' { 'ROLLBACK' }
        default    { 'AUDIT (read-only)' }
    }
    Write-Host ''
    Write-Host "  Windows Server Hardening Toolkit v$Version" -ForegroundColor Cyan
    Write-Rule
    Write-Host ('  {0,-10}: {1}' -f 'Mode', $label) -ForegroundColor $(if ($RunMode -eq 'Audit') { 'Gray' } else { 'Yellow' })
}

function Write-RunSummary {
    param($Run)

    $summary = $Run.Summary
    $scoreColor = if ($null -eq $summary.Score) { 'Gray' } elseif ($summary.Score -ge 90) { 'Green' } elseif ($summary.Score -ge 70) { 'Yellow' } else { 'Red' }
    $scoreText = if ($null -eq $summary.Score) { 'n/a' } else { "$($summary.Score) / 100" }

    Write-Host ('  {0,-10}: {1} ({2}, {3} build {4})' -f 'Computer', $Run.ComputerName, $Run.System.Role, $Run.System.OSName, $Run.System.OSBuild)
    Write-Host ('  {0,-10}: {1}' -f 'Profile', $Run.Profile)
    Write-Host ('  {0,-10}: {1}' -f 'Session', $Run.SessionId)
    Write-Rule
    Write-Host ('  {0,-10}: ' -f 'Score') -NoNewline
    Write-Host ('{0}   Grade {1}' -f $scoreText, $summary.Grade) -ForegroundColor $scoreColor
    Write-Host ('  {0,-10}: ' -f 'Results') -NoNewline
    Write-Host ('{0} compliant  ' -f $summary.Pass) -ForegroundColor Green -NoNewline
    Write-Host ('{0} remediated  ' -f $summary.Fixed) -ForegroundColor Cyan -NoNewline
    Write-Host ('{0} non-compliant  ' -f $summary.Fail) -ForegroundColor Yellow -NoNewline
    Write-Host ('{0} errors  ' -f $summary.Error) -ForegroundColor Red -NoNewline
    Write-Host ('{0} n/a' -f $summary.NotApplicable) -ForegroundColor DarkGray

    $severityRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $open = @($Run.Results | Where-Object { $_.Status -eq 'Fail' -or $_.Status -eq 'Error' } |
        Sort-Object -Property @{ Expression = { $severityRank[[string]$_.Severity] } }, Id)
    if ($open.Count -gt 0) {
        Write-Host ''
        Write-Host '  Top open findings' -ForegroundColor White
        foreach ($finding in ($open | Select-Object -First 10)) {
            $color = switch ($finding.Severity) { 'Critical' { 'Red' } 'High' { 'Yellow' } default { 'Gray' } }
            Write-Host ('   {0,-10} {1,-9} {2}' -f "[$($finding.Severity)]", $finding.Id, $finding.Title) -ForegroundColor $color
        }
        if ($open.Count -gt 10) {
            Write-Host ("   ... and {0} more (see the report)" -f ($open.Count - 10)) -ForegroundColor DarkGray
        }
    }

    if ($summary.RebootRequired) {
        Write-Host ''
        Write-Host '  A restart is required for some changes to take effect.' -ForegroundColor Yellow
    }

    if (@($Run.Reports).Count -gt 0) {
        Write-Host ''
        Write-Host '  Reports' -ForegroundColor White
        foreach ($report in $Run.Reports) {
            Write-Host "   $report"
        }
    }
    if ($Run.Mode -eq 'Remediate' -and $summary.Fixed -gt 0) {
        Write-Host ''
        Write-Host "  Roll back with: .\Harden-WindowsServer.ps1 -Mode Rollback -SessionId $($Run.SessionId)" -ForegroundColor DarkGray
    }
    Write-Host ''
}

# --- v1 compatibility --------------------------------------------------------------------------
if ($Rollback) { $Mode = 'Rollback' }
elseif ($ReportOnly) { $Mode = 'Audit' }
if ($Modules -and $Modules -ne 'All') {
    $legacyMap = @{
        SMB = 'SMB'; NTLM = 'Authentication'; AuditPolicy = 'AuditLogging'; Firewall = 'Firewall'; Services = 'Services'
        AccountPolicy = 'AccountPolicy'; Registry = 'System'; WindowsUpdate = 'WindowsUpdate'
    }
    $Category = @($Modules -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object {
            if ($legacyMap.ContainsKey($_)) { $legacyMap[$_] } else { $_ }
        })
}

try {
    $module = Import-HardeningModule
    Write-Banner -Version $module.Version -RunMode $Mode

    $common = @{ ProfileName = $ProfileName }
    foreach ($name in @('ProfilePath', 'OutputPath')) {
        if ($PSBoundParameters.ContainsKey($name)) { $common[$name] = $PSBoundParameters[$name] }
    }
    if ($Category) { $common.Category = $Category }
    if ($ControlId) { $common.ControlId = $ControlId }
    if ($ExcludeControlId) { $common.ExcludeControlId = $ExcludeControlId }

    switch ($Mode) {
        'Rollback' {
            $parameters = @{ Force = $Force; WhatIf = [bool]$WhatIfPreference }
            if ($SessionId) { $parameters.SessionId = $SessionId }
            if ($OutputPath) { $parameters.OutputPath = $OutputPath }
            if ($PSBoundParameters.ContainsKey('Confirm')) { $parameters.Confirm = $PSBoundParameters['Confirm'] }

            $results = @(Undo-HardeningRemediation @parameters)
            Write-Rule
            foreach ($item in $results) {
                $color = switch ($item.Status) { 'Restored' { 'Green' } 'Skipped' { 'Yellow' } default { 'Red' } }
                Write-Host ('   {0,-9} {1,-9} {2}' -f $item.Status, $item.ControlId, $item.Detail) -ForegroundColor $color
            }
            $failedCount = @($results | Where-Object { $_.Status -eq 'Failed' }).Count
            Write-Host ''
            Write-Host ("  Rollback finished: {0} restored, {1} skipped, {2} failed." -f @($results | Where-Object { $_.Status -eq 'Restored' }).Count, @($results | Where-Object { $_.Status -eq 'Skipped' }).Count, $failedCount)
            Write-Host ''
            exit $(if ($failedCount -gt 0) { 1 } else { 0 })
        }

        'Harden' {
            if ($ComputerName) {
                throw 'Remote hardening is not supported. Run -Mode Harden locally, or audit remote servers with -Mode Audit -ComputerName.'
            }
            $parameters = $common + @{ ReportFormat = $ReportFormat; Force = $Force; WhatIf = [bool]$WhatIfPreference }
            if ($PSBoundParameters.ContainsKey('Confirm')) { $parameters.Confirm = $PSBoundParameters['Confirm'] }
            $runs = @(Invoke-HardeningRemediation @parameters)
        }

        default {
            $parameters = $common + @{ ReportFormat = $ReportFormat }
            if ($ComputerName) {
                $parameters.ComputerName = $ComputerName
                if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) { $parameters.Credential = $Credential }
            }
            $runs = @(Invoke-HardeningAudit @parameters -ErrorAction Continue)
            if ($ComputerName -and $runs.Count -lt @($ComputerName).Count) {
                foreach ($runItem in $runs) { Write-RunSummary -Run $runItem }
                Write-Host "  $(@($ComputerName).Count - $runs.Count) of $(@($ComputerName).Count) remote audit(s) failed." -ForegroundColor Red
                exit 2
            }
        }
    }

    foreach ($runItem in $runs) {
        Write-RunSummary -Run $runItem
    }
    $open = 0
    foreach ($runItem in $runs) { $open += $runItem.Summary.Fail + $runItem.Summary.Error }
    exit $(if ($open -gt 0) { 1 } else { 0 })
}
catch {
    Write-Host ''
    Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ''
    exit 2
}
