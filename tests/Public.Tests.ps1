BeforeDiscovery {
    Import-Module -Name (Join-Path (Split-Path $PSScriptRoot -Parent) 'src\WindowsServerHardening\WindowsServerHardening.psd1') -Force
}

InModuleScope WindowsServerHardening {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    }

    Describe 'Get-HardeningControl' {
        It 'filters by wildcard ID' {
            @(Get-HardeningControl -Id 'SMB-*').Count | Should -Be 7
        }

        It 'filters by category and severity' {
            $controls = @(Get-HardeningControl -Category 'Authentication' -Severity 'Critical')
            $controls.Count | Should -BeGreaterThan 0
            @($controls | Where-Object { $_.Category -ne 'Authentication' -or $_.Severity -ne 'Critical' }).Count | Should -Be 0
        }

        It 'returns the effective controls of a profile' {
            Mock Get-HardeningSystemInfo { New-TestSystemInfo }
            $ids = @(Get-HardeningControl -ProfileName 'WebServer' | ForEach-Object { $_.Id })
            $ids | Should -Contain 'NET-007'
            $ids | Should -Not -Contain 'FW-006'
        }
    }

    Describe 'Get-HardeningProfile' {
        It 'lists the built-in profiles' {
            @(Get-HardeningProfile | ForEach-Object { $_.Name }) | Should -Be @('DomainController', 'MemberServer', 'WebServer')
        }

        It 'returns a resolved profile' {
            (Get-HardeningProfile -Name 'WebServer').Parameters.InactivityTimeoutSeconds | Should -Be 600
        }
    }

    Describe 'Invoke-HardeningAudit' {
        BeforeAll {
            Mock Get-HardeningSystemInfo { New-TestSystemInfo }
            Mock Get-SmbServerState { New-ControlState -Value $false }
            Mock Get-RegistryState { New-ControlState -Value $null -Exists $false -Display 'Not configured' }
            $outputRoot = Join-Path $TestDrive 'audit'
            $run = Invoke-HardeningAudit -ControlId 'SMB-*' -OutputPath $outputRoot -ReportFormat Html, Json, Csv -WarningAction SilentlyContinue
        }

        It 'evaluates the selected controls' {
            $run.Mode | Should -Be 'Audit'
            $run.Profile | Should -Be 'MemberServer'
            @($run.Results).Count | Should -Be 7
            ($run.Results | Where-Object { $_.Id -eq 'SMB-001' }).Status | Should -Be 'Pass'
            ($run.Results | Where-Object { $_.Id -eq 'SMB-003' }).Status | Should -Be 'Fail'
        }

        It 'writes the requested reports and a log' {
            @($run.Reports).Count | Should -Be 3
            foreach ($report in $run.Reports) { Test-Path -LiteralPath $report | Should -BeTrue }
            Test-Path -LiteralPath $run.LogPath | Should -BeTrue
        }

        It 'does not create a rollback session' {
            Test-Path -LiteralPath (Join-Path $outputRoot 'sessions') | Should -BeFalse
        }

        It 'fails when no control matches' {
            { Invoke-HardeningAudit -ControlId 'NOPE-*' -OutputPath $outputRoot -NoReport -WarningAction SilentlyContinue } | Should -Throw '*No controls matched*'
        }

        It 'exports reports for remote runs and continues after a failed server' {
            Mock Invoke-RemoteHardeningAudit {
                if ($ComputerName -eq 'BAD01') { throw 'WinRM cannot complete the operation.' }
                $result = New-HardeningResult -Control (New-TestControl)
                $result.Status = 'Pass'
                $remote = New-TestRun -Results @($result)
                $remote.ComputerName = $ComputerName
                $remote
            }
            $errors = $null
            $runs = @(Invoke-HardeningAudit -ComputerName 'SRV01', 'BAD01' -OutputPath $outputRoot -ErrorVariable errors -ErrorAction SilentlyContinue)
            $runs.Count | Should -Be 1
            $runs[0].ComputerName | Should -Be 'SRV01'
            @($runs[0].Reports).Count | Should -Be 2
            "$errors" | Should -Match 'BAD01'
        }
    }

    Describe 'Invoke-HardeningRemediation' {
        BeforeEach {
            Mock Get-HardeningSystemInfo { New-TestSystemInfo }
            Mock Assert-HardeningElevation { }
            $script:SmbEnabled = $true
            Mock Get-SmbServerState { New-ControlState -Value $script:SmbEnabled }
            Mock Set-SmbServerState { $script:SmbEnabled = $false }
        }

        It 'remediates, records the change and creates a session' {
            $outputRoot = Join-Path $TestDrive 'fix'
            $run = Invoke-HardeningRemediation -ControlId 'SMB-001' -OutputPath $outputRoot -NoReport -Force
            ($run.Results | Where-Object { $_.Id -eq 'SMB-001' }).Status | Should -Be 'Fixed'
            Should -Invoke Set-SmbServerState -Times 1
            $session = Get-HardeningSession -OutputPath $outputRoot
            $session.ChangeCount | Should -Be 1
            $session.Status | Should -Be 'Completed'
        }

        It 'changes nothing with -WhatIf' {
            $run = Invoke-HardeningRemediation -ControlId 'SMB-001' -OutputPath (Join-Path $TestDrive 'whatif') -NoReport -WhatIf
            ($run.Results | Where-Object { $_.Id -eq 'SMB-001' }).Status | Should -Be 'Fail'
            Should -Invoke Set-SmbServerState -Times 0
        }

        It 'requires elevation' {
            Mock Assert-HardeningElevation { throw 'requires an elevated PowerShell session' }
            { Invoke-HardeningRemediation -ControlId 'SMB-001' -OutputPath (Join-Path $TestDrive 'denied') -Force } | Should -Throw '*elevated*'
            Should -Invoke Set-SmbServerState -Times 0
        }
    }

    Describe 'SMB server provider' {
        It 'reads, sets and restores a property' {
            Mock Get-SmbServerConfiguration { [pscustomobject]@{ EnableSMB1Protocol = $true } }
            Mock Set-SmbServerConfiguration { }
            $control = New-TestControl -Override @{ Type = 'SmbServer'; Target = @{ Property = 'EnableSMB1Protocol' }; Expected = $false }

            (Get-SmbServerState -Control $control).Value | Should -BeTrue
            Set-SmbServerState -Control $control
            Should -Invoke Set-SmbServerConfiguration -Times 1 -ParameterFilter { $EnableSMB1Protocol -eq $false -and $Force }

            $outcome = Restore-SmbServerState -Change @{ Target = @{ Property = 'EnableSMB1Protocol' }; Previous = @{ Value = $true } }
            $outcome.Status | Should -Be 'Restored'
            Should -Invoke Set-SmbServerConfiguration -Times 1 -ParameterFilter { $EnableSMB1Protocol -eq $true }
        }
    }

    Describe 'Firewall rule provider' {
        BeforeAll {
            $control = New-TestControl -Override @{
                Type     = 'FirewallRule'
                Target   = @{ Name = 'WSH-Block-Telnet-In'; DisplayName = 'Block Telnet'; Direction = 'Inbound'; Protocol = 'TCP'; LocalPort = '23' }
                Expected = 'Present'
            }
        }

        It 'reports a missing rule as absent' {
            Mock Get-NetFirewallRule { }
            $state = Get-FirewallRuleState -Control $control
            $state.Value | Should -Be 'Absent'
            $state.Exists | Should -BeFalse
        }

        It 'reports a disabled rule as inactive' {
            Mock Get-NetFirewallRule { [pscustomobject]@{ Enabled = 'False'; Action = 'Block' } }
            (Get-FirewallRuleState -Control $control).Value | Should -Be 'Inactive'
        }

        It 'creates a missing rule in the toolkit group' {
            Mock New-NetFirewallRule { }
            Set-FirewallRuleState -Control $control -State (New-ControlState -Value 'Absent' -Exists $false)
            Should -Invoke New-NetFirewallRule -Times 1 -ParameterFilter { $Name -eq 'WSH-Block-Telnet-In' -and $Action -eq 'Block' -and $LocalPort -eq '23' -and $Group -eq 'Windows Server Hardening Toolkit' }
        }

        It 're-enables an existing rule instead of creating a duplicate' {
            Mock New-NetFirewallRule { }
            Mock Set-NetFirewallRule { }
            Set-FirewallRuleState -Control $control -State (New-ControlState -Value 'Inactive' -Exists $true)
            Should -Invoke Set-NetFirewallRule -Times 1
            Should -Invoke New-NetFirewallRule -Times 0
        }

        It 'removes a rule it created on rollback' {
            Mock Remove-NetFirewallRule { }
            $outcome = Restore-FirewallRuleState -Change @{ Target = @{ Name = 'WSH-Block-Telnet-In' }; Previous = @{ Exists = $false } }
            $outcome.Status | Should -Be 'Restored'
            Should -Invoke Remove-NetFirewallRule -Times 1 -ParameterFilter { $Name -eq 'WSH-Block-Telnet-In' }
        }
    }
}
