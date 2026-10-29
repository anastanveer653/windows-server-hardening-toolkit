#Requires -Version 5.1
<#
.SYNOPSIS
    Renders docs/sample-report.html from synthetic data, so the report can be previewed without a server.

.DESCRIPTION
    Builds a run object for a fictitious member server from the real control catalog, with a
    deterministic mix of results, and renders it with the same code path as a real audit. The
    report is labelled "Sample data".

.PARAMETER OutputPath
    HTML file to write.

.EXAMPLE
    .\tools\New-SampleReport.ps1 -OutputPath .\docs\sample-report.html
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Developer tool with console output.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$module = Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath '..\src\WindowsServerHardening\WindowsServerHardening.psd1') -Force -PassThru

# Run inside the module scope to reuse the private result, summary and rendering functions.
$html = & $module {
    $profileData = Get-HardeningProfileData -Name 'MemberServer'
    $controls = @(Resolve-HardeningControlSet -ProfileData $profileData)
    $start = [datetime]'2026-10-29T09:30:00'
    $sampleHost = 'SRV-APP-01'

    # Deterministic "random" outcome per control so the sample stays stable between builds.
    # SHA256 rather than MD5 so the tool also works on FIPS-enabled systems.
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $results = foreach ($control in $controls) {
        $result = New-HardeningResult -Control $control -ComputerName $sampleHost
        $roll = [int]$hasher.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($control.Id))[0]
        if ($control.Roles -and $control.Roles -notcontains 'MemberServer') {
            $result.Status = 'NotApplicable'
            $result.Detail = "Applies only to: $($control.Roles -join ', ') (this computer: MemberServer)."
        }
        elseif ($control.Type -eq 'Service' -and $roll -lt 90) {
            $result.Status = 'NotApplicable'
            $result.Detail = "Service '$($control.Target.Name)' is not installed."
        }
        elseif ($roll -lt 175) {
            $result.Status = 'Pass'
            $result.Actual = switch ($control.Type) {
                'AuditPolicy'     { Format-AuditPolicyFlag -Flag (ConvertTo-AuditPolicyFlag -Setting $control.Expected) }
                'FirewallProfile' { 'Domain={0}; Private={0}; Public={0}' -f $control.Expected }
                'Service'         { 'StartType=Disabled, Status=Stopped' }
                default           { Format-HardeningValue -Value $control.Expected }
            }
            $result.Detail = 'Compliant.'
        }
        elseif ($roll -lt 250) {
            $result.Status = 'Fail'
            $result.Actual = if ($control.Type -eq 'Registry') { 'Not configured' } else { 'Non-compliant value' }
            $result.Detail = 'Not compliant.'
        }
        else {
            $result.Status = 'Error'
            $result.Detail = 'Access is denied.'
        }
        $result.Timestamp = $start
        $result
    }

    $run = [pscustomobject]@{
        SessionId       = '20261029-093000-5a3c1e'
        Mode            = 'Audit'
        Profile         = $profileData.Name
        ComputerName    = $sampleHost
        StartTime       = $start
        EndTime         = $start.AddSeconds(38)
        DurationSeconds = 38
        ModuleVersion   = $script:ModuleVersion
        IsSample        = $true
        System          = [pscustomobject]@{
            ComputerName      = $sampleHost
            Domain            = 'corp.example.com'
            Role              = 'MemberServer'
            OSName            = 'Microsoft Windows Server 2022 Datacenter'
            OSVersion         = '10.0.20348'
            OSBuild           = '20348'
            IsServer          = $true
            LastBootTime      = $start.AddDays(-6)
            PowerShellVersion = '5.1.20348.2849'
            IsElevated        = $true
        }
        Summary         = Get-HardeningSummary -Results @($results)
        Results         = @($results)
    }
    ConvertTo-HardeningHtml -Document (ConvertTo-HardeningReportDocument -Run $run)
}

$fullPath = [System.IO.Path]::GetFullPath($OutputPath)
[void][System.IO.Directory]::CreateDirectory((Split-Path -Path $fullPath -Parent))
[System.IO.File]::WriteAllText($fullPath, $html, [System.Text.UTF8Encoding]::new($false))
Write-Host "Wrote sample report to $OutputPath"
