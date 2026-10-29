<#
.SYNOPSIS
    End-to-end test of the toolkit on a real Windows Server: audit, harden, verify, roll back.

.DESCRIPTION
    Runs the complete lifecycle against the operating system it is started on and checks every
    step:

      1. Audit           - completes without control errors.
      2. Harden          - completes without errors; every remediable control becomes compliant.
      3. Verify          - a fresh audit confirms that the changes persisted.
      4. Idempotency     - a second hardening run changes nothing.
      5. Roll back       - every recorded change is restored without failures.
      6. Compare         - a final audit matches the baseline from step 1.

    The script writes an evidence file (integration-<computer>-<timestamp>.json) with the OS
    version, build, PowerShell and .NET versions, and the result of every check, together with the
    HTML/JSON reports of each phase.

    Run it only on a test server or VM (take a snapshot first). It changes security settings and
    then restores them. Use -AuditOnly for a read-only run that is safe on any server.

    Exit codes: 0 all checks passed, 1 one or more checks failed, 2 the test could not run.

.PARAMETER OutputPath
    Folder for evidence, reports, logs and rollback data.

.PARAMETER ExcludeControlId
    Controls to skip. Defaults to WU-005 (the online Windows Update scan), which can take minutes
    and needs internet or WSUS access.

.PARAMETER AuditOnly
    Run only the read-only audit checks.

.PARAMETER Force
    Do not ask for confirmation before hardening and rolling back (for CI and disposable VMs).

.EXAMPLE
    .\tests\Integration\Invoke-IntegrationTest.ps1

    Runs the full lifecycle on this server after asking for confirmation.

.EXAMPLE
    .\tests\Integration\Invoke-IntegrationTest.ps1 -AuditOnly

    Runs only the read-only checks.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive test runner with console output.')]
[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path -Path $env:ProgramData -ChildPath 'WindowsServerHardening-IntegrationTest'),

    [string[]]$ExcludeControlId = @('WU-005'),

    [switch]$AuditOnly,

    [switch]$Force
)

if ($PSVersionTable.PSVersion -lt [version]'5.1') {
    Write-Host "Windows PowerShell 5.1 or later is required (found $($PSVersionTable.PSVersion)). Install WMF 5.1: https://aka.ms/wmf51download" -ForegroundColor Red
    exit 2
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
$checks = [System.Collections.Generic.List[object]]::new()
$phases = [ordered]@{}

function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

function Add-Check {
    param(
        [string]$Name,
        [bool]$Passed,
        [string]$Detail = ''
    )

    $checks.Add([pscustomobject]@{ Name = $Name; Passed = $Passed; Detail = $Detail })
    if ($Passed) {
        Write-Host "  [PASS] $Name" -ForegroundColor Green
    }
    else {
        Write-Host "  [FAIL] $Name" -ForegroundColor Red
        if ($Detail) { Write-Host "         $Detail" -ForegroundColor Yellow }
    }
}

function Add-Phase {
    param(
        [string]$Name,
        [psobject]$Run
    )

    $phases[$Name] = [ordered]@{
        sessionId     = $Run.SessionId
        score         = $Run.Summary.Score
        grade         = $Run.Summary.Grade
        pass          = $Run.Summary.Pass
        fixed         = $Run.Summary.Fixed
        fail          = $Run.Summary.Fail
        error         = $Run.Summary.Error
        notApplicable = $Run.Summary.NotApplicable
        errors        = @($Run.Results | Where-Object { $_.Status -eq 'Error' } | ForEach-Object { "$($_.Id): $($_.Detail)" })
    }
    Write-Host ('  Score {0} ({1})  pass {2}  fixed {3}  fail {4}  error {5}  n/a {6}' -f $Run.Summary.Score, $Run.Summary.Grade, $Run.Summary.Pass, $Run.Summary.Fixed, $Run.Summary.Fail, $Run.Summary.Error, $Run.Summary.NotApplicable)
}

function Get-ErrorText {
    param([object[]]$Results)
    return ((@($Results) | Select-Object -First 10 | ForEach-Object { "$($_.Id): $($_.Detail)" }) -join ' | ')
}

function Get-StatusMap {
    param([psobject]$Run)
    $map = @{}
    foreach ($result in $Run.Results) { $map[$result.Id] = $result.Status }
    return $map
}

$exitCode = 2
$environment = [ordered]@{}
try {
    Write-Section 'Environment'
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $framework = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name 'Release' -ErrorAction SilentlyContinue
    $identity = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent())
    $environment = [ordered]@{
        computerName      = $env:COMPUTERNAME
        osName            = [string]$os.Caption
        osVersion         = [string]$os.Version
        osBuild           = [string]$os.BuildNumber
        powerShellVersion = $PSVersionTable.PSVersion.ToString()
        powerShellEdition = if ($PSVersionTable.PSObject.Properties['PSEdition']) { [string]$PSVersionTable.PSEdition } else { 'Desktop' }
        dotNetRelease     = if ($null -ne $framework) { [int]$framework.Release } else { $null }
        uiCulture         = (Get-UICulture).Name
        elevated          = $identity.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        startTime         = (Get-Date).ToString('o')
    }
    foreach ($key in $environment.Keys) { Write-Host ('  {0,-18}: {1}' -f $key, $environment[$key]) }

    if (-not $environment.elevated) {
        throw 'The integration test must run in an elevated PowerShell session (Run as Administrator).'
    }

    $module = Import-Module -Name (Join-Path -Path $repositoryRoot -ChildPath 'src\WindowsServerHardening\WindowsServerHardening.psd1') -Force -PassThru
    $environment.toolkitVersion = $module.Version.ToString()
    $common = @{ OutputPath = $OutputPath; ExcludeControlId = $ExcludeControlId; WarningAction = 'SilentlyContinue' }

    Write-Section '1. Baseline audit'
    $baseline = Invoke-HardeningAudit @common -ReportFormat Html, Json
    Add-Phase -Name 'baseline' -Run $baseline
    $errors = @($baseline.Results | Where-Object { $_.Status -eq 'Error' })
    Add-Check -Name 'Audit completes without control errors' -Passed ($errors.Count -eq 0) -Detail (Get-ErrorText $errors)
    Add-Check -Name 'Audit evaluates the catalog' -Passed ($baseline.Summary.Evaluated -ge 50) -Detail "Evaluated: $($baseline.Summary.Evaluated)"
    Add-Check -Name 'Audit writes HTML and JSON reports' -Passed (@($baseline.Reports | Where-Object { Test-Path -LiteralPath $_ }).Count -eq 2)

    if (-not $AuditOnly) {
        if (-not $Force) {
            Write-Host ''
            Write-Host '  The next steps HARDEN this server and then ROLL BACK the changes.' -ForegroundColor Yellow
            Write-Host '  Only continue on a test server or VM with a snapshot.' -ForegroundColor Yellow
            $answer = Read-Host '  Type YES to continue'
            if ($answer -ne 'YES') { throw 'Cancelled by the user before hardening.' }
        }

        Write-Section '2. Harden'
        $hardened = Invoke-HardeningRemediation @common -Force -ReportFormat Html, Json
        Add-Phase -Name 'harden' -Run $hardened
        $errors = @($hardened.Results | Where-Object { $_.Status -eq 'Error' })
        Add-Check -Name 'Remediation completes without errors' -Passed ($errors.Count -eq 0) -Detail (Get-ErrorText $errors)
        $remediable = @($hardened.Results | Where-Object { -not $_.AuditOnly -and $_.Status -ne 'NotApplicable' })
        $open = @($remediable | Where-Object { $_.Status -ne 'Pass' -and $_.Status -ne 'Fixed' })
        Add-Check -Name 'Every remediable control is compliant after hardening' -Passed ($open.Count -eq 0) -Detail (Get-ErrorText $open)
        Add-Check -Name 'Hardening recorded rollback data' -Passed (@(Get-HardeningSession -OutputPath $OutputPath -Id $hardened.SessionId).Count -eq 1)

        Write-Section '3. Verify with a fresh audit'
        $verified = Invoke-HardeningAudit @common -ReportFormat Html, Json
        Add-Phase -Name 'verify' -Run $verified
        $remediableIds = @($remediable | ForEach-Object { $_.Id })
        $regressed = @($verified.Results | Where-Object { $remediableIds -contains $_.Id -and $_.Status -ne 'Pass' })
        Add-Check -Name 'Remediated settings persist' -Passed ($regressed.Count -eq 0) -Detail (Get-ErrorText $regressed)
        Add-Check -Name 'Score improved' -Passed ([int]$verified.Summary.Score -ge [int]$baseline.Summary.Score) -Detail "Baseline $($baseline.Summary.Score), after hardening $($verified.Summary.Score)"

        Write-Section '4. Idempotency'
        $again = Invoke-HardeningRemediation @common -Force -NoReport
        Add-Phase -Name 'idempotency' -Run $again
        $changed = @($again.Results | Where-Object { $_.Status -eq 'Fixed' })
        Add-Check -Name 'A second hardening run changes nothing' -Passed ($changed.Count -eq 0) -Detail (Get-ErrorText $changed)

        Write-Section '5. Roll back'
        $rollback = @(Undo-HardeningRemediation -SessionId $hardened.SessionId -OutputPath $OutputPath -Force)
        $failedRestores = @($rollback | Where-Object { $_.Status -eq 'Failed' })
        $skippedIds = @($rollback | Where-Object { $_.Status -eq 'Skipped' } | ForEach-Object { $_.ControlId })
        $phases['rollback'] = [ordered]@{
            restored = @($rollback | Where-Object { $_.Status -eq 'Restored' }).Count
            skipped  = $skippedIds
            failed   = @($failedRestores | ForEach-Object { "$($_.ControlId): $($_.Detail)" })
        }
        Write-Host ('  Restored {0}  skipped {1}  failed {2}' -f $phases.rollback.restored, $skippedIds.Count, $failedRestores.Count)
        Add-Check -Name 'Every change is restored without failures' -Passed ($failedRestores.Count -eq 0) -Detail ((@($failedRestores) | ForEach-Object { "$($_.ControlId): $($_.Detail)" }) -join ' | ')
        $recorded = (Get-HardeningSession -OutputPath $OutputPath -Id $hardened.SessionId).ChangeCount
        Add-Check -Name 'Rollback covers every recorded change' -Passed ($rollback.Count -eq $recorded) -Detail "Recorded $recorded change(s), rolled back $($rollback.Count)"

        Write-Section '6. Compare with the baseline'
        $restored = Invoke-HardeningAudit @common -ReportFormat Html, Json
        Add-Phase -Name 'afterRollback' -Run $restored
        $before = Get-StatusMap -Run $baseline
        $after = Get-StatusMap -Run $restored
        $differences = @(foreach ($id in ($before.Keys | Sort-Object)) {
                if ($before[$id] -ne $after[$id] -and $skippedIds -notcontains $id) { "${id}: $($before[$id]) -> $($after[$id])" }
            })
        Add-Check -Name 'Configuration after rollback matches the baseline' -Passed ($differences.Count -eq 0) -Detail (($differences | Select-Object -First 15) -join ' | ')
    }

    $exitCode = if (@($checks | Where-Object { -not $_.Passed }).Count -eq 0) { 0 } else { 1 }
}
catch {
    Write-Host ''
    Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Add-Check -Name 'Test run completed' -Passed $false -Detail $_.Exception.Message
    $exitCode = 2
}
finally {
    [void][System.IO.Directory]::CreateDirectory($OutputPath)
    $evidence = [ordered]@{
        schemaVersion = '1.0'
        result        = if ($exitCode -eq 0) { 'Passed' } else { 'Failed' }
        mode          = if ($AuditOnly) { 'AuditOnly' } else { 'FullLifecycle' }
        environment   = $environment
        phases        = $phases
        checks        = @($checks)
        endTime       = (Get-Date).ToString('o')
    }
    $evidencePath = Join-Path -Path $OutputPath -ChildPath ('integration-{0}-{1}.json' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    [System.IO.File]::WriteAllText($evidencePath, (ConvertTo-Json -InputObject $evidence -Depth 6), [System.Text.UTF8Encoding]::new($false))

    $passed = @($checks | Where-Object { $_.Passed }).Count
    Write-Section 'Summary'
    $color = if ($exitCode -eq 0) { 'Green' } else { 'Red' }
    Write-Host ("  {0} of {1} checks passed on {2} (build {3})." -f $passed, $checks.Count, $environment['osName'], $environment['osBuild']) -ForegroundColor $color
    Write-Host "  Evidence: $evidencePath"
    Write-Host "  Reports : $(Join-Path -Path $OutputPath -ChildPath 'reports')"
    Write-Host ''
}
exit $exitCode
