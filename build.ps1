#Requires -Version 5.1
<#
.SYNOPSIS
    Development tasks: static analysis, tests, generated documentation and the sample report.

.PARAMETER Task
    One or more of: Analyze, Test, Docs, SampleReport, All (default).

.PARAMETER CI
    Write NUnit test results and JaCoCo coverage to .\out and fail the build on any problem.

.EXAMPLE
    .\build.ps1

    Runs static analysis and the test suite, then regenerates docs\CONTROLS.md and docs\sample-report.html.

.EXAMPLE
    .\build.ps1 -Task Test -CI

    Runs the tests the way the CI pipeline does.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Build script with console output.')]
[CmdletBinding()]
param(
    [ValidateSet('Analyze', 'Test', 'Docs', 'SampleReport', 'All')]
    [string[]]$Task = 'All',

    [switch]$CI
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$moduleRoot = Join-Path -Path $root -ChildPath 'src\WindowsServerHardening'
$outDir = Join-Path -Path $root -ChildPath 'out'
if ($Task -contains 'All') { $Task = @('Analyze', 'Test', 'Docs', 'SampleReport') }

function Invoke-AnalyzeTask {
    Import-Module -Name PSScriptAnalyzer -ErrorAction Stop
    $settings = Join-Path -Path $root -ChildPath 'PSScriptAnalyzerSettings.psd1'
    $targets = @($moduleRoot, (Join-Path $root 'tools'), (Join-Path $root 'tests\Integration'), (Join-Path $root 'Harden-WindowsServer.ps1'), (Join-Path $root 'build.ps1'))
    $findings = @(foreach ($target in $targets) { Invoke-ScriptAnalyzer -Path $target -Recurse -Settings $settings })
    if ($findings.Count -gt 0) {
        $findings | Format-Table -Property Severity, RuleName, ScriptName, Line, Message -AutoSize -Wrap | Out-String -Width 220 | Write-Host
        throw "PSScriptAnalyzer reported $($findings.Count) finding(s)."
    }
    Write-Host 'PSScriptAnalyzer: no findings.' -ForegroundColor Green
}

function Import-PesterModule {
    # Pester 5.7 and later call the HashSet(int capacity) constructor, which needs .NET Framework 4.7.2.
    # Windows Server 2016 ships with 4.6.2, so use Pester 5.5/5.6 there.
    $pesterParameters = @{ Name = 'Pester'; MinimumVersion = '5.5.0'; ErrorAction = 'Stop'; PassThru = $true }
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        $framework = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name 'Release' -ErrorAction SilentlyContinue
        if ($null -eq $framework -or $framework.Release -lt 461808) {
            $pesterParameters.MaximumVersion = '5.6.99'
            Write-Host '.NET Framework is older than 4.7.2: using Pester 5.6 or earlier.' -ForegroundColor Yellow
        }
    }
    try {
        $pester = Import-Module @pesterParameters
    }
    catch {
        $version = if ($pesterParameters.Contains('MaximumVersion')) { '5.6.1' } else { '5.7.1' }
        throw ("No compatible Pester module was found. Install it with:`n" +
            "    Install-Module -Name Pester -RequiredVersion $version -Scope CurrentUser -Force -SkipPublisherCheck`n" +
            'or copy an offline copy (Save-Module) into Documents\WindowsPowerShell\Modules.')
    }
    Write-Host "Using Pester $($pester.Version)"
}

function Invoke-TestTask {
    param([bool]$CI)

    Import-PesterModule
    $configuration = New-PesterConfiguration
    $configuration.Run.Path = Join-Path -Path $root -ChildPath 'tests'
    $configuration.Run.PassThru = $true
    $configuration.Output.Verbosity = if ($CI) { 'Detailed' } else { 'Normal' }
    $configuration.CodeCoverage.Enabled = $true
    $configuration.CodeCoverage.Path = @(Get-ChildItem -Path $moduleRoot -Filter '*.ps1' -Recurse | ForEach-Object { $_.FullName })
    $configuration.CodeCoverage.OutputPath = Join-Path -Path $outDir -ChildPath 'coverage.xml'
    $configuration.CodeCoverage.OutputFormat = 'JaCoCo'
    if ($CI) {
        $configuration.TestResult.Enabled = $true
        $configuration.TestResult.OutputFormat = 'NUnitXml'
        $configuration.TestResult.OutputPath = Join-Path -Path $outDir -ChildPath 'testResults.xml'
    }

    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    $result = Invoke-Pester -Configuration $configuration
    if ($null -eq $result -or -not $result.PSObject.Properties['FailedCount']) {
        throw 'Pester did not return a test result. See the error above.'
    }
    if ($result.PSObject.Properties['CodeCoverage'] -and $result.CodeCoverage) {
        $coverage = $result.CodeCoverage
        $percent = if ($coverage.CommandsAnalyzedCount -gt 0) { [Math]::Round($coverage.CommandsExecutedCount / $coverage.CommandsAnalyzedCount * 100, 1) } else { 0 }
        Write-Host "Code coverage: $percent% ($($coverage.CommandsExecutedCount)/$($coverage.CommandsAnalyzedCount) commands)" -ForegroundColor Cyan
    }
    if ($result.FailedCount -gt 0 -or $result.Result -ne 'Passed') {
        throw "$($result.FailedCount) test(s) failed."
    }
}

function Invoke-DocsTask {
    & (Join-Path -Path $root -ChildPath 'tools\Export-ControlDocs.ps1') -OutputPath (Join-Path $root 'docs\CONTROLS.md')
}

function Invoke-SampleReportTask {
    & (Join-Path -Path $root -ChildPath 'tools\New-SampleReport.ps1') -OutputPath (Join-Path $root 'docs\sample-report.html')
}

foreach ($item in $Task) {
    Write-Host "== $item ==" -ForegroundColor Cyan
    switch ($item) {
        'Analyze'      { Invoke-AnalyzeTask }
        'Test'         { Invoke-TestTask -CI $CI.IsPresent }
        'Docs'         { Invoke-DocsTask }
        'SampleReport' { Invoke-SampleReportTask }
    }
}
