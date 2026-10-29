BeforeDiscovery {
    Import-Module -Name (Join-Path (Split-Path $PSScriptRoot -Parent) 'src\WindowsServerHardening\WindowsServerHardening.psd1') -Force
}

InModuleScope WindowsServerHardening {
    Describe 'Control catalog' {
        BeforeAll {
            $controls = @(Get-HardeningCatalog -Force)
            $memberServer = Get-HardeningProfileData -Name 'MemberServer'
            $prefix = @{
                SMB = 'SMB'; Authentication = 'AUTH'; AccountPolicy = 'ACCT'; AuditLogging = 'LOG'; Firewall = 'FW'
                Services = 'SVC'; System = 'SYS'; RemoteDesktop = 'RDP'; Network = 'NET'; WindowsUpdate = 'WU'
            }
        }

        It 'loads at least 100 controls' {
            $controls.Count | Should -BeGreaterOrEqual 100
        }

        It 'uses unique control IDs' {
            @($controls | Group-Object -Property Id | Where-Object { $_.Count -gt 1 }).Count | Should -Be 0
        }

        It 'uses well-formed IDs that match the category prefix' {
            $bad = foreach ($control in $controls) {
                if (-not $prefix.ContainsKey($control.Category) -or $control.Id -notmatch "^$($prefix[$control.Category])-\d{3}$") { $control.Id }
            }
            $bad | Should -BeNullOrEmpty
        }

        It 'gives every control a title, rationale and benchmark reference' {
            $bad = foreach ($control in $controls) {
                if ($control.Title.Length -gt 90 -or $control.Rationale.Length -lt 30 -or -not $control.Benchmark) { $control.Id }
            }
            $bad | Should -BeNullOrEmpty
        }

        It 'uses valid MITRE ATT&CK technique IDs' {
            $bad = foreach ($control in $controls) {
                foreach ($technique in $control.MitreAttack) {
                    if ($technique -notmatch '^T\d{4}(\.\d{3})?$') { "$($control.Id): $technique" }
                }
            }
            $bad | Should -BeNullOrEmpty
        }

        It 'only links to HTTPS references' {
            $bad = foreach ($control in $controls) {
                foreach ($link in $control.Links) { if ($link -notmatch '^https://') { "$($control.Id): $link" } }
            }
            $bad | Should -BeNullOrEmpty
        }

        It 'targets HKLM with a value type that matches the expected value for registry controls' {
            $bad = foreach ($control in @($controls | Where-Object { $_.Type -eq 'Registry' })) {
                $typeOk = switch ($control.Target.ValueType) {
                    'DWord'  { $control.Expected -is [int] }
                    'String' { $control.Expected -is [string] }
                    default  { $false }
                }
                if ($control.Target.Path -notmatch '^HKLM:\\' -or -not $typeOk) { $control.Id }
            }
            $bad | Should -BeNullOrEmpty
        }

        It 'uses well-formed subcategory GUIDs and valid settings for audit policy controls' {
            $bad = foreach ($control in @($controls | Where-Object { $_.Type -eq 'AuditPolicy' })) {
                $validSetting = @('Success', 'Failure', 'SuccessAndFailure') -contains $control.Expected
                if ($control.Target.SubcategoryGuid -notmatch '^\{0CCE92[0-9A-F]{2}-69AE-11D9-BED3-505054503030\}$' -or -not $validSetting) { $control.Id }
            }
            $bad | Should -BeNullOrEmpty
        }

        It 'does not define the same audit subcategory twice' {
            $guids = @($controls | Where-Object { $_.Type -eq 'AuditPolicy' } | ForEach-Object { $_.Target.SubcategoryGuid })
            @($guids | Group-Object | Where-Object { $_.Count -gt 1 }).Count | Should -Be 0
        }

        It 'does not define the same registry value twice' {
            $values = @($controls | Where-Object { $_.Type -eq 'Registry' } | ForEach-Object { "$($_.Target.Path)\$($_.Target.Name)" })
            @($values | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name }) | Should -BeNullOrEmpty
        }

        It 'marks every custom check as audit-only with manual remediation guidance' {
            $bad = foreach ($control in @($controls | Where-Object { $_.Type -eq 'Custom' })) {
                if (-not $control.AuditOnly -or -not $control.Target.Contains('ManualRemediation')) { $control.Id }
            }
            $bad | Should -BeNullOrEmpty
        }

        It 'implements a handler for every custom check' {
            $handled = @('PendingUpdates', 'UpdateRecency', 'DepPolicy', 'CredentialGuard', 'RdpFirewallScope')
            $bad = @($controls | Where-Object { $_.Type -eq 'Custom' -and $handled -notcontains $_.Target.Check } | ForEach-Object { $_.Id })
            $bad | Should -BeNullOrEmpty
        }

        It 'documents the operational impact of every opt-in control' {
            $bad = @($controls | Where-Object { $_.OptIn -and -not $_.Impact } | ForEach-Object { $_.Id })
            $bad | Should -BeNullOrEmpty
        }

        It 'declares every profile parameter in the MemberServer profile' {
            $bad = @($controls | Where-Object { $_.Parameter -and -not $memberServer.Parameters.Contains($_.Parameter) } | ForEach-Object { $_.Id })
            $bad | Should -BeNullOrEmpty
        }

        It 'keeps catalog defaults in sync with the MemberServer profile parameters' {
            $bad = foreach ($control in @($controls | Where-Object { $_.Parameter })) {
                if ([string]$memberServer.Parameters[$control.Parameter] -ne [string]$control.Expected) { $control.Id }
            }
            $bad | Should -BeNullOrEmpty
        }

        It 'generates remediation text for every control' {
            @($controls | Where-Object { -not $_.Remediation -or -not $_.ExpectedDisplay } | ForEach-Object { $_.Id }) | Should -BeNullOrEmpty
        }
    }

    Describe 'Control validation' {
        BeforeAll {
            $valid = @{
                Id = 'TST-001'; Title = 'Test'; Category = 'Test'; Severity = 'High'; Type = 'Registry'
                Target = @{ Path = 'HKLM:\SOFTWARE\Test'; Name = 'Value' }; Expected = 1; Rationale = 'Because.'
            }
        }

        It 'rejects a control without <Field>' -TestCases @(
            @{ Field = 'Id' }, @{ Field = 'Title' }, @{ Field = 'Severity' }, @{ Field = 'Type' }, @{ Field = 'Target' }, @{ Field = 'Rationale' }, @{ Field = 'Expected' }
        ) {
            $definition = $valid.Clone()
            $definition.Remove($Field)
            { ConvertTo-HardeningControl -Definition $definition } | Should -Throw "*$Field*"
        }

        It 'rejects an unknown severity' {
            $definition = $valid.Clone()
            $definition.Severity = 'Urgent'
            { ConvertTo-HardeningControl -Definition $definition } | Should -Throw '*Severity*'
        }

        It 'rejects a registry control without a value name' {
            $definition = $valid.Clone()
            $definition.Target = @{ Path = 'HKLM:\SOFTWARE\Test' }
            { ConvertTo-HardeningControl -Definition $definition } | Should -Throw '*Target.Name*'
        }

        It 'rejects a Range control without Minimum' {
            $definition = $valid.Clone()
            $definition.Operator = 'Range'
            { ConvertTo-HardeningControl -Definition $definition } | Should -Throw '*Minimum*'
        }

        It 'rejects unknown roles' {
            $definition = $valid.Clone()
            $definition.Roles = @('FileServer')
            { ConvertTo-HardeningControl -Definition $definition } | Should -Throw '*role*'
        }

        It 'defaults registry controls to DWord and the Equals operator' {
            $control = ConvertTo-HardeningControl -Definition $valid
            $control.Target.ValueType | Should -Be 'DWord'
            $control.Operator | Should -Be 'Equals'
        }

        It 'forces custom checks to be audit-only' {
            $definition = $valid.Clone()
            $definition.Type = 'Custom'
            $definition.Target = @{ Check = 'DepPolicy' }
            (ConvertTo-HardeningControl -Definition $definition).AuditOnly | Should -BeTrue
        }
    }
}
