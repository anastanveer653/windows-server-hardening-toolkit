# Runs Harden-WindowsServer.ps1 in a child process with -File, the way scheduled tasks, RMM tools
# and cmd.exe call it. Only read-only audits of a few controls are executed.

BeforeAll {
    $root = Split-Path -Path $PSScriptRoot -Parent
    $cli = Join-Path -Path $root -ChildPath 'Harden-WindowsServer.ps1'
    $shell = (Get-Process -Id $PID).Path

    function Invoke-Cli {
        param([string[]]$Arguments)
        # Windows PowerShell 5.1 turns redirected native stderr into terminating errors when the caller
        # (for example build.ps1) uses $ErrorActionPreference = 'Stop'.
        $ErrorActionPreference = 'Continue'
        $output = & $shell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $cli @Arguments 2>&1 | Out-String
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
    }
}

Describe 'Harden-WindowsServer.ps1 command line' {
    It 'accepts comma separated lists through -File' {
        $outputPath = Join-Path $TestDrive 'lists'
        $result = Invoke-Cli -Arguments @('-ControlId', 'SMB-001,SMB-003', '-ReportFormat', 'Json,Csv', '-OutputPath', $outputPath)
        $result.ExitCode | Should -BeIn @(0, 1) -Because $result.Output
        @(Get-ChildItem -Path (Join-Path $outputPath 'reports') -Filter '*.json').Count | Should -Be 1
        @(Get-ChildItem -Path (Join-Path $outputPath 'reports') -Filter '*.csv').Count | Should -Be 1
        $report = Get-Content -Path (Get-ChildItem -Path (Join-Path $outputPath 'reports') -Filter '*.json').FullName -Raw | ConvertFrom-Json
        @($report.results | ForEach-Object { $_.id }) | Should -Be @('SMB-001', 'SMB-003')
    }

    It 'rejects an unknown report format with exit code 2' {
        $result = Invoke-Cli -Arguments @('-ControlId', 'SMB-001', '-ReportFormat', 'Json,Pdf', '-OutputPath', (Join-Path $TestDrive 'invalid'))
        $result.ExitCode | Should -Be 2
        $result.Output | Should -Match 'Invalid -ReportFormat'
    }

    It 'does not bind stray values to -Mode' {
        $result = Invoke-Cli -Arguments @('-ControlId', 'SMB-001,', 'Harden', '-OutputPath', (Join-Path $TestDrive 'stray'))
        $result.ExitCode | Should -Not -Be 0
        # PowerShell 7 prints the message; Windows PowerShell 5.1 wraps and interleaves it with
        # NativeCommandError records but always includes the stable error ID.
        $result.Output | Should -Match 'positional\s+parameter|PositionalParameterNotFound'
        $result.Output | Should -Not -Match 'HARDEN \(changes will be applied\)'
        Test-Path -Path (Join-Path $TestDrive 'stray\sessions') | Should -BeFalse
    }
}
