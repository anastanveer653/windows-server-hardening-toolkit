BeforeDiscovery {
    Import-Module -Name (Join-Path (Split-Path $PSScriptRoot -Parent) 'src\WindowsServerHardening\WindowsServerHardening.psd1') -Force
}

# End-to-end: remediate real registry values (under Pester's TestRegistry: drive), then roll the
# session back and verify the registry is exactly as it was. No administrator rights required.
InModuleScope WindowsServerHardening {
    Describe 'Remediation and rollback' {
        BeforeAll {
            . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
            Mock Assert-HardeningElevation { }

            New-Item -Path 'TestRegistry:\Existing' -Force | Out-Null
            New-ItemProperty -Path 'TestRegistry:\Existing' -Name 'Level' -Value 3 -PropertyType DWord | Out-Null
            New-ItemProperty -Path 'TestRegistry:\Existing' -Name 'Untouched' -Value 'keep' -PropertyType String | Out-Null

            $controls = @(
                New-TestControl -Override @{ Id = 'TST-001'; Target = @{ Path = 'TestRegistry:\Existing'; Name = 'Level'; ValueType = 'DWord' }; Expected = 5 }
                New-TestControl -Override @{ Id = 'TST-002'; Target = @{ Path = 'TestRegistry:\Policies\Created'; Name = 'First'; ValueType = 'DWord' }; Expected = 1 }
                New-TestControl -Override @{ Id = 'TST-003'; Target = @{ Path = 'TestRegistry:\Policies\Created'; Name = 'Second'; ValueType = 'String' }; Expected = 'on' }
                New-TestControl -Override @{ Id = 'TST-004'; Target = @{ Path = 'TestRegistry:\Existing'; Name = 'Untouched'; ValueType = 'String' }; Expected = 'keep' }
            )

            $outputRoot = Join-Path $TestDrive 'output'
            $session = New-HardeningSession -Mode Remediate -OutputPath $outputRoot -ProfileName 'Test'
            $run = Invoke-HardeningRun -Mode Remediate -Controls $controls -ProfileData ([ordered]@{ Name = 'Test'; Parameters = [ordered]@{} }) `
                -SystemInfo (New-TestSystemInfo) -Session $session -Cmdlet (New-TestCmdlet)
            $session.Status = 'Completed'
            Save-HardeningSessionInfo -Session $session
        }

        It 'remediates the non-compliant settings and leaves compliant ones alone' {
            ($run.Results | Where-Object { $_.Id -eq 'TST-001' }).Status | Should -Be 'Fixed'
            ($run.Results | Where-Object { $_.Id -eq 'TST-002' }).Status | Should -Be 'Fixed'
            ($run.Results | Where-Object { $_.Id -eq 'TST-003' }).Status | Should -Be 'Fixed'
            ($run.Results | Where-Object { $_.Id -eq 'TST-004' }).Status | Should -Be 'Pass'
            (Get-ItemProperty -Path 'TestRegistry:\Existing').Level | Should -Be 5
            (Get-ItemProperty -Path 'TestRegistry:\Policies\Created').Second | Should -Be 'on'
            $run.Score | Should -Be 100
        }

        It 'records one change per remediated control before it is applied' {
            $changes = @(Read-HardeningChange -SessionPath $session.SessionPath)
            $changes.Count | Should -Be 3
            $changes[0].ControlId | Should -Be 'TST-001'
            $changes[0].Previous.Exists | Should -BeTrue
            $changes[0].Previous.Value | Should -Be 3
            $changes[1].Previous.Exists | Should -BeFalse
            $changes[1].Previous.Extra.CreatedKeyRoot | Should -Be 'TestRegistry:\Policies'
        }

        It 'lists the session with its change count' {
            $info = Get-HardeningSession -OutputPath $outputRoot -Id $session.Id
            $info.Mode | Should -Be 'Remediate'
            $info.ChangeCount | Should -Be 3
            $info.RolledBack | Should -BeFalse
        }

        It 'previews the rollback with -WhatIf without changing anything' {
            $preview = @(Undo-HardeningRemediation -SessionId $session.Id -OutputPath $outputRoot -WhatIf)
            $preview.Count | Should -Be 0
            (Get-ItemProperty -Path 'TestRegistry:\Existing').Level | Should -Be 5
            (Get-HardeningSession -OutputPath $outputRoot -Id $session.Id).RolledBack | Should -BeFalse
        }

        It 'restores every setting and removes keys it created' {
            $results = @(Undo-HardeningRemediation -SessionId $session.Id -OutputPath $outputRoot -Force)
            $results.Count | Should -Be 3
            @($results | Where-Object { $_.Status -ne 'Restored' }).Count | Should -Be 0
            @($results | ForEach-Object { $_.ControlId }) | Should -Be @('TST-003', 'TST-002', 'TST-001')

            (Get-ItemProperty -Path 'TestRegistry:\Existing').Level | Should -Be 3
            (Get-ItemProperty -Path 'TestRegistry:\Existing').Untouched | Should -Be 'keep'
            Test-Path -Path 'TestRegistry:\Policies' | Should -BeFalse
        }

        It 'marks the session as rolled back and refuses a second rollback' {
            (Get-HardeningSession -OutputPath $outputRoot -Id $session.Id).RolledBack | Should -BeTrue
            { Undo-HardeningRemediation -SessionId $session.Id -OutputPath $outputRoot -Force } | Should -Throw '*already rolled back*'
        }

        It 'reports when no session is left to roll back' {
            { Undo-HardeningRemediation -OutputPath $outputRoot -Force } | Should -Throw '*No remediation session*'
        }
    }
}
