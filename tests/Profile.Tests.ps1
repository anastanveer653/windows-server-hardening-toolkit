BeforeDiscovery {
    Import-Module -Name (Join-Path (Split-Path $PSScriptRoot -Parent) 'src\WindowsServerHardening\WindowsServerHardening.psd1') -Force
}

InModuleScope WindowsServerHardening {
    Describe 'Profile loading' {
        It 'loads the built-in profile <_>' -ForEach @('MemberServer', 'DomainController', 'WebServer') {
            $profileData = Get-HardeningProfileData -Name $_
            $profileData.Name | Should -Be $_
            $profileData.Parameters.Count | Should -BeGreaterThan 0
        }

        It 'selects DomainController for Auto on a domain controller' {
            (Get-HardeningProfileData -Name 'Auto' -SystemInfo ([pscustomobject]@{ Role = 'DomainController' })).Name | Should -Be 'DomainController'
        }

        It 'selects MemberServer for Auto on other roles' {
            (Get-HardeningProfileData -Name 'Auto' -SystemInfo ([pscustomobject]@{ Role = 'StandaloneServer' })).Name | Should -Be 'MemberServer'
        }

        It 'inherits parameters and merges lists through Extends' {
            $dc = Get-HardeningProfileData -Name 'DomainController'
            $dc.Parameters.MinimumPasswordLength | Should -Be 14
            $dc.Parameters.SecurityLogMaxSizeKB | Should -Be 4194304
            $dc.AuditOnlyControls | Should -Contain 'ACCT-*'
        }

        It 'resolves a custom profile that extends a built-in profile' {
            $path = Join-Path $TestDrive 'Contoso.json'
            Set-Content -Path $path -Value '{ "Name": "Contoso", "Extends": "WebServer", "ExcludeControls": ["SVC-001"], "Parameters": { "MinimumPasswordLength": 16 } }'
            $custom = Get-HardeningProfileData -Path $path
            $custom.Name | Should -Be 'Contoso'
            $custom.Parameters.MinimumPasswordLength | Should -Be 16
            $custom.Parameters.InactivityTimeoutSeconds | Should -Be 600
            $custom.EnableControls | Should -Contain 'NET-007'
            $custom.ExcludeControls | Should -Contain 'FW-006'
            $custom.ExcludeControls | Should -Contain 'SVC-001'
        }

        It 'rejects an unknown profile and lists the available ones' {
            { Get-HardeningProfileData -Name 'Kiosk' } | Should -Throw '*Available profiles*MemberServer*'
        }

        It 'rejects invalid JSON with the file name' {
            $path = Join-Path $TestDrive 'broken.json'
            Set-Content -Path $path -Value '{ "Name": '
            { Get-HardeningProfileData -Path $path } | Should -Throw '*broken.json*'
        }

        It 'detects circular inheritance' {
            Set-Content -Path (Join-Path $TestDrive 'A.json') -Value '{ "Name": "A", "Extends": "B" }'
            Set-Content -Path (Join-Path $TestDrive 'B.json') -Value '{ "Name": "B", "Extends": "A" }'
            { Get-HardeningProfileData -Path (Join-Path $TestDrive 'A.json') } | Should -Throw '*nested too deeply*'
        }
    }

    Describe 'Resolve-HardeningControlSet' {
        BeforeAll {
            $memberServer = Get-HardeningProfileData -Name 'MemberServer'
        }

        It 'references only existing controls from the built-in profile <_>' -ForEach @('MemberServer', 'DomainController', 'WebServer') {
            $warnings = $null
            $null = @(Resolve-HardeningControlSet -ProfileData (Get-HardeningProfileData -Name $_) -WarningVariable warnings -WarningAction SilentlyContinue)
            @($warnings).Count | Should -Be 0
        }

        It 'leaves opt-in controls out by default' {
            $ids = @(Resolve-HardeningControlSet -ProfileData $memberServer | ForEach-Object { $_.Id })
            $ids | Should -Not -Contain 'SYS-014'
            $ids | Should -Not -Contain 'NET-007'
            $ids | Should -Contain 'SMB-001'
        }

        It 'includes opt-in controls enabled by the profile' {
            $ids = @(Resolve-HardeningControlSet -ProfileData (Get-HardeningProfileData -Name 'WebServer') | ForEach-Object { $_.Id })
            $ids | Should -Contain 'NET-007'
            $ids | Should -Contain 'NET-008'
            $ids | Should -Not -Contain 'FW-006'
        }

        It 'includes an opt-in control that is selected explicitly' {
            $ids = @(Resolve-HardeningControlSet -ProfileData $memberServer -ControlId 'SYS-014' | ForEach-Object { $_.Id })
            $ids | Should -Be @('SYS-014')
        }

        It 'filters by wildcard control ID, category and exclusion' {
            @(Resolve-HardeningControlSet -ProfileData $memberServer -ControlId 'SMB-*' | ForEach-Object { $_.Category } | Select-Object -Unique) | Should -Be @('SMB')
            @(Resolve-HardeningControlSet -ProfileData $memberServer -Category 'Firewall' | ForEach-Object { $_.Category } | Select-Object -Unique) | Should -Be @('Firewall')
            @(Resolve-HardeningControlSet -ProfileData $memberServer -Category 'SMB' -ExcludeControlId 'SMB-005' | ForEach-Object { $_.Id }) | Should -Not -Contain 'SMB-005'
        }

        It 'applies profile parameters to the expected value and its description' {
            $profileData = Get-HardeningProfileData -Name 'MemberServer'
            $profileData.Parameters.MinimumPasswordLength = 20
            $control = Resolve-HardeningControlSet -ProfileData $profileData -ControlId 'ACCT-001'
            $control.Expected | Should -Be 20
            $control.ExpectedDisplay | Should -Be '>= 20'
            $control.Remediation | Should -Match 'MinimumPasswordLength = 20'
        }

        It 'does not modify the cached catalog when applying parameters' {
            $profileData = Get-HardeningProfileData -Name 'MemberServer'
            $profileData.Parameters.MinimumPasswordLength = 20
            $null = Resolve-HardeningControlSet -ProfileData $profileData -ControlId 'ACCT-001'
            (Get-HardeningCatalog | Where-Object { $_.Id -eq 'ACCT-001' }).Expected | Should -Be 14
        }

        It 'marks AuditOnlyControls as audit-only' {
            $controls = @(Resolve-HardeningControlSet -ProfileData (Get-HardeningProfileData -Name 'DomainController') -Category 'AccountPolicy')
            $controls.Count | Should -BeGreaterThan 0
            @($controls | Where-Object { -not $_.AuditOnly }).Count | Should -Be 0
            $controls[0].Remediation | Should -Match '^Manual'
        }

        It 'warns about profile entries that match no control' {
            $profileData = Get-HardeningProfileData -Name 'MemberServer'
            $profileData.ExcludeControls = @('XYZ-999')
            $warnings = $null
            $null = @(Resolve-HardeningControlSet -ProfileData $profileData -WarningVariable warnings -WarningAction SilentlyContinue)
            "$warnings" | Should -Match 'XYZ-999'
        }
    }
}
