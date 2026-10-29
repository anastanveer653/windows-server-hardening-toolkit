BeforeDiscovery {
    Import-Module -Name (Join-Path (Split-Path $PSScriptRoot -Parent) 'src\WindowsServerHardening\WindowsServerHardening.psd1') -Force
}

InModuleScope WindowsServerHardening {
    Describe 'Invoke-HardeningControl' {
        BeforeAll {
            . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        }

        BeforeEach {
            $script:TestLog = [System.Collections.Generic.List[string]]::new()
            Mock Add-HardeningChange { $script:TestLog.Add('record') }
            Mock Set-RegistryState { $script:TestLog.Add('set') }
        }

        It 'reports Pass for a compliant setting' {
            Mock Get-RegistryState { New-ControlState -Value 1 }
            $result = Invoke-HardeningControl -Control (New-TestControl) -Context (New-TestContext)
            $result.Status | Should -Be 'Pass'
            $result.Actual | Should -Be '1'
            Should -Invoke Set-RegistryState -Times 0
        }

        It 'reports Fail in audit mode without changing anything' {
            Mock Get-RegistryState { New-ControlState -Value 0 }
            $result = Invoke-HardeningControl -Control (New-TestControl) -Context (New-TestContext -Mode Audit)
            $result.Status | Should -Be 'Fail'
            Should -Invoke Set-RegistryState -Times 0
            Should -Invoke Add-HardeningChange -Times 0
        }

        It 'records the previous state before remediating, then verifies the change' {
            $script:Reads = 0
            Mock Get-RegistryState {
                $script:Reads++
                if ($script:Reads -eq 1) { New-ControlState -Value 0 } else { New-ControlState -Value 1 }
            }
            $result = Invoke-HardeningControl -Control (New-TestControl) -Context (New-TestContext -Mode Remediate)
            $result.Status | Should -Be 'Fixed'
            $result.Detail | Should -Match 'Previous value: 0'
            @($script:TestLog) | Should -Be @('record', 'set')
            $script:Reads | Should -Be 2
        }

        It 'flags remediation that does not persist as Error' {
            Mock Get-RegistryState { New-ControlState -Value 0 }
            $result = Invoke-HardeningControl -Control (New-TestControl) -Context (New-TestContext -Mode Remediate)
            $result.Status | Should -Be 'Error'
            $result.Detail | Should -Match 'verification failed'
        }

        It 'does not change anything when ShouldProcess declines (WhatIf)' {
            Mock Get-RegistryState { New-ControlState -Value 0 }
            $cmdlet = New-TestCmdlet -Allow $false
            $result = Invoke-HardeningControl -Control (New-TestControl) -Context (New-TestContext -Mode Remediate -Cmdlet $cmdlet)
            $result.Status | Should -Be 'Fail'
            $result.Detail | Should -Match 'WhatIf'
            $cmdlet.Calls | Should -Be 1
            Should -Invoke Set-RegistryState -Times 0
            Should -Invoke Add-HardeningChange -Times 0
        }

        It 'never remediates audit-only controls' {
            Mock Get-RegistryState { New-ControlState -Value 0 }
            $cmdlet = New-TestCmdlet
            $result = Invoke-HardeningControl -Control (New-TestControl -Override @{ AuditOnly = $true }) -Context (New-TestContext -Mode Remediate -Cmdlet $cmdlet)
            $result.Status | Should -Be 'Fail'
            $result.Detail | Should -Match 'audit-only'
            $cmdlet.Calls | Should -Be 0
            Should -Invoke Set-RegistryState -Times 0
        }

        It 'reports provider exceptions as Error with the message' {
            Mock Get-RegistryState { throw 'Access is denied' }
            $result = Invoke-HardeningControl -Control (New-TestControl) -Context (New-TestContext)
            $result.Status | Should -Be 'Error'
            $result.Detail | Should -Be 'Access is denied'
        }

        It 'reports NotApplicable when the provider says so' {
            Mock Get-RegistryState { New-ControlState -Applicable $false -Reason 'Key missing' }
            $result = Invoke-HardeningControl -Control (New-TestControl) -Context (New-TestContext)
            $result.Status | Should -Be 'NotApplicable'
            $result.Detail | Should -Be 'Key missing'
        }

        It 'skips controls restricted to other roles' {
            Mock Get-RegistryState { New-ControlState -Value 0 }
            $result = Invoke-HardeningControl -Control (New-TestControl -Override @{ Roles = @('DomainController') }) -Context (New-TestContext -Role 'MemberServer')
            $result.Status | Should -Be 'NotApplicable'
            Should -Invoke Get-RegistryState -Times 0
        }

        It 'skips controls that exclude the current role' {
            $result = Invoke-HardeningControl -Control (New-TestControl -Override @{ ExcludeRoles = @('DomainController') }) -Context (New-TestContext -Role 'DomainController')
            $result.Status | Should -Be 'NotApplicable'
        }

        It 'skips controls that need a newer Windows build' {
            Mock Get-RegistryState { New-ControlState -Value 0 }
            $context = New-TestContext
            $context.System.OSBuild = '9600'
            $result = Invoke-HardeningControl -Control (New-TestControl -Override @{ MinimumBuild = 14393 }) -Context $context
            $result.Status | Should -Be 'NotApplicable'
            $result.Detail | Should -Match 'Windows Server 2016'
            Should -Invoke Get-RegistryState -Times 0
        }

        It 'evaluates controls on the minimum build and later' {
            Mock Get-RegistryState { New-ControlState -Value 1 }
            $context = New-TestContext
            $context.System.OSBuild = '14393'
            (Invoke-HardeningControl -Control (New-TestControl -Override @{ MinimumBuild = 14393 }) -Context $context).Status | Should -Be 'Pass'
        }

        It 'uses a precomputed compliance flag from the provider' {
            Mock Get-RegistryState { New-ControlState -Value 'anything' -Compliant $true }
            (Invoke-HardeningControl -Control (New-TestControl) -Context (New-TestContext)).Status | Should -Be 'Pass'
        }

        It 'sets RebootRequired only for fixed controls that need a restart' {
            $script:Reads = 0
            Mock Get-RegistryState {
                $script:Reads++
                if ($script:Reads -eq 1) { New-ControlState -Value 0 } else { New-ControlState -Value 1 }
            }
            $result = Invoke-HardeningControl -Control (New-TestControl -Override @{ RebootRequired = $true }) -Context (New-TestContext -Mode Remediate)
            $result.RebootRequired | Should -BeTrue
        }
    }

    Describe 'Get-HardeningOSRelease' {
        It 'maps build <Build> to <Release>' -TestCases @(
            @{ Build = 9200; Release = 'Windows Server 2012' }
            @{ Build = 9600; Release = 'Windows Server 2012 R2' }
            @{ Build = 14393; Release = 'Windows Server 2016' }
            @{ Build = 17763; Release = 'Windows Server 2019' }
            @{ Build = 20348; Release = 'Windows Server 2022' }
            @{ Build = 26100; Release = 'Windows Server 2025' }
        ) {
            Get-HardeningOSRelease -Build $Build | Should -Be $Release
        }
    }

    Describe 'Get-HardeningSummary' {
        BeforeAll {
            function New-SummaryResult {
                param($Status, $Severity, $Category = 'Test', $Reboot = $false)
                [pscustomobject]@{ Status = $Status; Severity = $Severity; Category = $Category; RebootRequired = $Reboot }
            }
        }

        It 'weights the score by severity and ignores not-applicable controls' {
            $summary = Get-HardeningSummary -Results @(
                (New-SummaryResult -Status Pass -Severity Critical)
                (New-SummaryResult -Status Fail -Severity High)
                (New-SummaryResult -Status NotApplicable -Severity Low)
            )
            $summary.Score | Should -Be 66
            $summary.Grade | Should -Be 'D'
            $summary.ComplianceRate | Should -Be 50
            $summary.Evaluated | Should -Be 2
            $summary.NotApplicable | Should -Be 1
        }

        It 'counts errors as non-compliant and open findings by severity' {
            $summary = Get-HardeningSummary -Results @(
                (New-SummaryResult -Status Fixed -Severity High)
                (New-SummaryResult -Status Error -Severity High)
                (New-SummaryResult -Status Fail -Severity Low)
            )
            $summary.Score | Should -Be 45
            $summary.OpenBySeverity.High | Should -Be 1
            $summary.OpenBySeverity.Low | Should -Be 1
            $summary.OpenBySeverity.Critical | Should -Be 0
        }

        It 'returns no score when nothing could be evaluated' {
            $summary = Get-HardeningSummary -Results @((New-SummaryResult -Status NotApplicable -Severity High))
            $summary.Score | Should -BeNullOrEmpty
            $summary.Grade | Should -Be 'N/A'
        }

        It 'handles an empty result set' {
            $summary = Get-HardeningSummary -Results @()
            $summary.Total | Should -Be 0
            $summary.Score | Should -BeNullOrEmpty
        }

        It 'computes per-category compliance and the reboot flag' {
            $summary = Get-HardeningSummary -Results @(
                (New-SummaryResult -Status Pass -Severity Low -Category 'SMB')
                (New-SummaryResult -Status Fail -Severity Low -Category 'SMB')
                (New-SummaryResult -Status Fixed -Severity Low -Category 'Network' -Reboot $true)
            )
            ($summary.Categories | Where-Object { $_.Name -eq 'SMB' }).Rate | Should -Be 50
            ($summary.Categories | Where-Object { $_.Name -eq 'Network' }).Rate | Should -Be 100
            $summary.RebootRequired | Should -BeTrue
        }

        It 'assigns grade <Grade> to score <Score>' -TestCases @(
            @{ Passed = 9; Failed = 1; Grade = 'A'; Score = 90 }
            @{ Passed = 8; Failed = 2; Grade = 'B'; Score = 80 }
            @{ Passed = 7; Failed = 3; Grade = 'C'; Score = 70 }
            @{ Passed = 6; Failed = 4; Grade = 'D'; Score = 60 }
            @{ Passed = 5; Failed = 5; Grade = 'F'; Score = 50 }
        ) {
            $results = @(1..$Passed | ForEach-Object { New-SummaryResult -Status Pass -Severity Low }) + @(1..$Failed | ForEach-Object { New-SummaryResult -Status Fail -Severity Low })
            $summary = Get-HardeningSummary -Results $results
            $summary.Score | Should -Be $Score
            $summary.Grade | Should -Be $Grade
        }
    }
}
