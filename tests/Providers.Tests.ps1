BeforeDiscovery {
    Import-Module -Name (Join-Path (Split-Path $PSScriptRoot -Parent) 'src\WindowsServerHardening\WindowsServerHardening.psd1') -Force
}

InModuleScope WindowsServerHardening {
    BeforeAll {
        . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
        $fixtures = Join-Path $PSScriptRoot 'Fixtures'
    }

    Describe 'Registry provider (real registry via TestRegistry:)' {
        It 'reports a missing value as not configured' {
            $state = Get-RegistryState -Control (New-TestControl -Override @{ Target = @{ Path = 'TestRegistry:\Missing'; Name = 'Value' } })
            $state.Exists | Should -BeFalse
            $state.Value | Should -BeNullOrEmpty
            $state.Display | Should -Be 'Not configured'
            $state.Extra.CreatedKeyRoot | Should -Be 'TestRegistry:\Missing'
        }

        It 'uses the documented Windows default for a missing value' {
            $state = Get-RegistryState -Control (New-TestControl -Override @{ Target = @{ Path = 'TestRegistry:\Missing'; Name = 'Value'; AbsentValue = 1 } })
            $state.Value | Should -Be 1
            $state.Display | Should -Be 'Not configured (Windows default: 1)'
        }

        It 'applies a Windows default only from AbsentValueMinimumBuild onwards' {
            $control = New-TestControl -Override @{ Target = @{ Path = 'TestRegistry:\Missing'; Name = 'Value'; AbsentValue = 0; AbsentValueMinimumBuild = 9600 }; Expected = 0 }
            $old = New-TestContext
            $old.System.OSBuild = '9200'
            $new = New-TestContext
            $new.System.OSBuild = '14393'

            (Get-RegistryState -Control $control -Context $old).Value | Should -BeNullOrEmpty
            (Get-RegistryState -Control $control -Context $old).Display | Should -Be 'Not configured'
            (Get-RegistryState -Control $control -Context $new).Value | Should -Be 0
        }

        It 'is not applicable when the key is missing and SkipIfKeyMissing is set' {
            $state = Get-RegistryState -Control (New-TestControl -Override @{ Target = @{ Path = 'TestRegistry:\Driver'; Name = 'Start'; SkipIfKeyMissing = $true } })
            $state.Applicable | Should -BeFalse
        }

        It 'reads an existing value and its kind' {
            New-Item -Path 'TestRegistry:\Existing' -Force | Out-Null
            New-ItemProperty -Path 'TestRegistry:\Existing' -Name 'Value' -Value 3 -PropertyType DWord | Out-Null
            $state = Get-RegistryState -Control (New-TestControl -Override @{ Target = @{ Path = 'TestRegistry:\Existing'; Name = 'Value' } })
            $state.Exists | Should -BeTrue
            $state.Value | Should -Be 3
            $state.Extra.ValueKind | Should -Be 'DWord'
        }

        It 'creates missing keys and writes the expected value with the right type' {
            $control = New-TestControl -Override @{ Target = @{ Path = 'TestRegistry:\New\Deep'; Name = 'Text'; ValueType = 'String' }; Expected = 'Authorized use only' }
            Set-RegistryState -Control $control
            $key = Get-Item -Path 'TestRegistry:\New\Deep'
            $key.GetValue('Text') | Should -Be 'Authorized use only'
            $key.GetValueKind('Text') | Should -Be 'String'
        }

        It 'does not drop other values of an existing key' {
            New-Item -Path 'TestRegistry:\Shared' -Force | Out-Null
            New-ItemProperty -Path 'TestRegistry:\Shared' -Name 'Other' -Value 7 -PropertyType DWord | Out-Null
            Set-RegistryState -Control (New-TestControl -Override @{ Target = @{ Path = 'TestRegistry:\Shared'; Name = 'Value'; ValueType = 'DWord' } })
            (Get-ItemProperty -Path 'TestRegistry:\Shared').Other | Should -Be 7
        }

        It 'restores a previous value of a different kind' {
            New-Item -Path 'TestRegistry:\Kinds' -Force | Out-Null
            New-ItemProperty -Path 'TestRegistry:\Kinds' -Name 'Value' -Value @('a', 'b') -PropertyType MultiString | Out-Null
            $control = New-TestControl -Override @{ Target = @{ Path = 'TestRegistry:\Kinds'; Name = 'Value'; ValueType = 'DWord' } }
            $before = Get-RegistryState -Control $control
            Set-RegistryState -Control $control
            $change = ConvertTo-HashtableDeep -InputObject (ConvertFrom-Json -InputObject (ConvertTo-Json -Depth 6 -InputObject @{
                        Type = 'Registry'; Target = $control.Target; Previous = @{ Exists = $before.Exists; Value = $before.Value; Extra = $before.Extra }
                    }))
            $outcome = Restore-RegistryState -Change $change
            $outcome.Status | Should -Be 'Restored'
            $key = Get-Item -Path 'TestRegistry:\Kinds'
            $key.GetValueKind('Value') | Should -Be 'MultiString'
            @($key.GetValue('Value')) | Should -Be @('a', 'b')
        }

        It 'removes only keys it created when they become empty' {
            New-Item -Path 'TestRegistry:\Parent' -Force | Out-Null
            New-Item -Path 'TestRegistry:\Parent\Created\Leaf' -Force | Out-Null
            Remove-EmptyRegistryKey -Path 'TestRegistry:\Parent\Created\Leaf' -StopAt 'TestRegistry:\Parent\Created'
            Test-Path -Path 'TestRegistry:\Parent\Created' | Should -BeFalse
            Test-Path -Path 'TestRegistry:\Parent' | Should -BeTrue
        }

        It 'keeps a created key that still holds other values' {
            New-Item -Path 'TestRegistry:\Busy' -Force | Out-Null
            New-ItemProperty -Path 'TestRegistry:\Busy' -Name 'Keep' -Value 1 -PropertyType DWord | Out-Null
            Remove-EmptyRegistryKey -Path 'TestRegistry:\Busy' -StopAt 'TestRegistry:\Busy'
            Test-Path -Path 'TestRegistry:\Busy' | Should -BeTrue
        }
    }

    Describe 'Service provider' {
        It 'is not applicable when the service is not installed' {
            Mock Get-CimInstance { } -ParameterFilter { $ClassName -eq 'Win32_Service' }
            (Get-ServiceState -Control (New-TestControl -Override @{ Type = 'Service'; Target = @{ Name = 'Nope' }; Expected = 'Disabled' })).Applicable | Should -BeFalse
        }

        It 'maps the CIM start mode <StartMode> to <StartType>' -TestCases @(
            @{ StartMode = 'Auto'; StartType = 'Automatic' }
            @{ StartMode = 'Manual'; StartType = 'Manual' }
            @{ StartMode = 'Disabled'; StartType = 'Disabled' }
        ) {
            Mock Get-CimInstance { [pscustomobject]@{ Name = 'Spooler'; StartMode = $StartMode; State = 'Running' } } -ParameterFilter { $ClassName -eq 'Win32_Service' }
            Mock Get-ItemProperty { } -ParameterFilter { $Name -eq 'DelayedAutostart' }
            $state = Get-ServiceState -Control (New-TestControl -Override @{ Type = 'Service'; Target = @{ Name = 'Spooler' }; Expected = 'Disabled' })
            $state.Value | Should -Be $StartType
            $state.Extra.Status | Should -Be 'Running'
        }

        It 'queries the service by an escaped WQL filter' {
            Mock Get-CimInstance { } -ParameterFilter { $ClassName -eq 'Win32_Service' }
            $null = Get-HardeningServiceInfo -Name "odd'name"
            Should -Invoke Get-CimInstance -Times 1 -ParameterFilter { $Filter -eq "Name='odd\'name'" }
        }

        It 'stops a running service before disabling it' {
            Mock Get-CimInstance { [pscustomobject]@{ Name = 'Spooler'; StartMode = 'Auto'; State = 'Running' } } -ParameterFilter { $ClassName -eq 'Win32_Service' }
            Mock Stop-Service { }
            Mock Set-Service { }
            Set-ServiceState -Control (New-TestControl -Override @{ Type = 'Service'; Target = @{ Name = 'Spooler' }; Expected = 'Disabled' })
            Should -Invoke Stop-Service -Times 1 -ParameterFilter { $Name -eq 'Spooler' }
            Should -Invoke Set-Service -Times 1 -ParameterFilter { $Name -eq 'Spooler' -and $StartupType -eq 'Disabled' }
        }

        It 'restores the start type and restarts a service that was running' {
            Mock Set-Service { }
            Mock Start-Service { }
            $change = @{ Target = @{ Name = 'Spooler' }; Previous = @{ Value = 'Automatic'; Extra = @{ Status = 'Running'; DelayedAutoStart = $false } } }
            (Restore-ServiceState -Change $change).Status | Should -Be 'Restored'
            Should -Invoke Set-Service -Times 1 -ParameterFilter { $StartupType -eq 'Automatic' }
            Should -Invoke Start-Service -Times 1
        }
    }

    Describe 'Firewall profile provider' {
        BeforeAll {
            Mock Get-NetFirewallProfile {
                [pscustomobject]@{ Name = 'Domain'; Enabled = 'True'; LogMaxSizeKilobytes = 32767 }
                [pscustomobject]@{ Name = 'Private'; Enabled = 'True'; LogMaxSizeKilobytes = 4096 }
                [pscustomobject]@{ Name = 'Public'; Enabled = 'False'; LogMaxSizeKilobytes = 4096 }
            }
        }

        It 'reads one value per profile' {
            $state = Get-FirewallProfileState -Control (New-TestControl -Override @{ Type = 'FirewallProfile'; Target = @{ Property = 'Enabled' }; Expected = 'True' })
            $state.Value.Keys | Should -Be @('Domain', 'Private', 'Public')
            $state.Display | Should -Be 'Domain=True; Private=True; Public=False'
        }

        It 'changes only the non-compliant profiles' {
            Mock Set-NetFirewallProfile { }
            $control = New-TestControl -Override @{ Type = 'FirewallProfile'; Target = @{ Property = 'LogMaxSizeKilobytes' }; Expected = 16384; Operator = 'GreaterOrEqual' }
            $state = Get-FirewallProfileState -Control $control
            Set-FirewallProfileState -Control $control -State $state
            Should -Invoke Set-NetFirewallProfile -Times 2
            Should -Invoke Set-NetFirewallProfile -Times 0 -ParameterFilter { $Name -eq 'Domain' }
        }
    }

    Describe 'Audit policy provider' {
        It 'parses auditpol /backup output by GUID' {
            $settings = ConvertFrom-AuditPolicyBackup -Content (Get-Content -Path (Join-Path $fixtures 'auditpol-backup.csv'))
            $settings.Count | Should -Be 4
            $settings['{0CCE923F-69AE-11D9-BED3-505054503030}'] | Should -Be 3
            $settings['{0CCE9215-69AE-11D9-BED3-505054503030}'] | Should -Be 1
            $settings['{0CCE922B-69AE-11D9-BED3-505054503030}'] | Should -Be 0
        }

        It 'returns an empty table for empty input' {
            (ConvertFrom-AuditPolicyBackup -Content @()).Count | Should -Be 0
        }

        It 'requires <Expected> with current flag <Flag> -> <Result>' -TestCases @(
            @{ Flag = 1; Expected = 'Success'; Result = $true }
            @{ Flag = 1; Expected = 'SuccessAndFailure'; Result = $false }
            @{ Flag = 3; Expected = 'Failure'; Result = $true }
            @{ Flag = 2; Expected = 'Success'; Result = $false }
            @{ Flag = 0; Expected = 'Failure'; Result = $false }
        ) {
            $control = New-TestControl -Override @{ Type = 'AuditPolicy'; Target = @{ Subcategory = 'Logon'; SubcategoryGuid = '{0CCE9215-69AE-11D9-BED3-505054503030}' }; Expected = $Expected }
            Test-AuditPolicyState -Control $control -State (New-ControlState -Value $Flag) | Should -Be $Result
        }

        It 'adds missing bits without removing existing ones and invalidates the cache' {
            Mock Invoke-HardeningNativeCommand { [pscustomobject]@{ ExitCode = 0; Output = ''; Error = '' } }
            $context = New-TestContext -Mode Remediate
            $context.Cache['AuditPolicy'] = @{}
            $control = New-TestControl -Override @{ Type = 'AuditPolicy'; Target = @{ Subcategory = 'Logon'; SubcategoryGuid = '{0CCE9215-69AE-11D9-BED3-505054503030}' }; Expected = 'Failure' }
            Set-AuditPolicyState -Control $control -Context $context -State (New-ControlState -Value 1)
            Should -Invoke Invoke-HardeningNativeCommand -Times 1 -ParameterFilter {
                $FilePath -eq 'auditpol.exe' -and $ArgumentList -contains '/success:enable' -and $ArgumentList -contains '/failure:enable'
            }
            $context.Cache.Contains('AuditPolicy') | Should -BeFalse
        }

        It 'throws when auditpol fails' {
            Mock Invoke-HardeningNativeCommand { [pscustomobject]@{ ExitCode = 87; Output = 'The parameter is incorrect.'; Error = '' } }
            { Set-AuditPolicyFlag -Guid '{0CCE9215-69AE-11D9-BED3-505054503030}' -Flag 3 } | Should -Throw '*exit code 87*'
        }

        It 'runs auditpol only once per run, even when it fails' {
            Mock Get-AuditPolicySnapshot { throw 'auditpol /backup failed (exit code 1314).' }
            $context = New-TestContext
            $control = New-TestControl -Override @{ Type = 'AuditPolicy'; Target = @{ Subcategory = 'Logon'; SubcategoryGuid = '{0CCE9215-69AE-11D9-BED3-505054503030}' }; Expected = 'Success' }
            { Get-AuditPolicyState -Control $control -Context $context } | Should -Throw '*1314*'
            { Get-AuditPolicyState -Control $control -Context $context } | Should -Throw '*1314*'
            Should -Invoke Get-AuditPolicySnapshot -Times 1
        }
    }

    Describe 'Security policy provider' {
        BeforeAll {
            $policy = ConvertFrom-SecurityPolicyInf -Content (Get-Content -Path (Join-Path $fixtures 'secedit-export.inf'))
        }

        It 'parses sections and keys from a secedit export' {
            $policy['System Access']['MinimumPasswordLength'] | Should -Be '8'
            $policy['System Access']['NewGuestName'] | Should -Be '"Guest"'
            $policy['Version']['signature'] | Should -Be '"$CHICAGO$"'
        }

        It 'returns numeric values as numbers, including negative ones' {
            Mock Get-SecurityPolicySnapshot { $policy }
            $context = New-TestContext
            (Get-SecurityPolicyState -Control (New-TestControl -Override @{ Type = 'SecurityPolicy'; Target = @{ Key = 'MaximumPasswordAge' } }) -Context $context).Value | Should -Be -1
            (Get-SecurityPolicyState -Control (New-TestControl -Override @{ Type = 'SecurityPolicy'; Target = @{ Key = 'NewGuestName' } }) -Context $context).Value | Should -Be 'Guest'
            Should -Invoke Get-SecurityPolicySnapshot -Times 1
        }

        It 'reports keys that are not defined' {
            Mock Get-SecurityPolicySnapshot { $policy }
            $state = Get-SecurityPolicyState -Control (New-TestControl -Override @{ Type = 'SecurityPolicy'; Target = @{ Key = 'LockoutDuration' } }) -Context (New-TestContext)
            $state.Exists | Should -BeFalse
            $state.Display | Should -Be 'Not defined'
        }

        It 'writes a Unicode INF and applies it with secedit /configure' {
            $script:InfContent = $null
            Mock Invoke-HardeningNativeCommand {
                $cfg = $ArgumentList[[array]::IndexOf($ArgumentList, '/cfg') + 1]
                $script:InfContent = [System.IO.File]::ReadAllText($cfg, [System.Text.Encoding]::Unicode)
                [pscustomobject]@{ ExitCode = 0; Output = ''; Error = '' }
            }
            Set-SecurityPolicyValue -Section 'System Access' -Key 'MinimumPasswordLength' -Value 14
            $script:InfContent | Should -Match '\[System Access\]\r\nMinimumPasswordLength = 14'
            $script:InfContent | Should -Match 'signature="\$CHICAGO\$"'
            Should -Invoke Invoke-HardeningNativeCommand -Times 1 -ParameterFilter { $FilePath -eq 'secedit.exe' -and $ArgumentList -contains '/configure' }
        }

        It 'skips restoring a setting that was not defined before' {
            $outcome = Restore-SecurityPolicyState -Change @{ Target = @{ Key = 'LockoutDuration' }; Previous = @{ Exists = $false; Value = $null } }
            $outcome.Status | Should -Be 'Skipped'
        }
    }

    Describe 'Custom checks' {
        It 'skips the pending update scan when the profile disables it' {
            $context = New-TestContext
            $context.Parameters['SkipPendingUpdateScan'] = $true
            (Get-PendingUpdateState -Context $context).Applicable | Should -BeFalse
        }

        It 'reports the number of days since the latest update' {
            Mock Get-HotFix {
                [pscustomobject]@{ HotFixID = 'KB1'; InstalledOn = (Get-Date).AddDays(-40) }
                [pscustomobject]@{ HotFixID = 'KB2'; InstalledOn = (Get-Date).AddDays(-10) }
                [pscustomobject]@{ HotFixID = 'KB3'; InstalledOn = $null }
            }
            $state = Get-UpdateRecencyState
            $state.Value | Should -Be 10
            $state.Display | Should -Match 'KB2'
        }

        It 'refuses to remediate custom checks' {
            { Set-CustomState -Control (New-TestControl -Override @{ Type = 'Custom'; Target = @{ Check = 'DepPolicy' } }) } | Should -Throw '*audit-only*'
        }
    }
}
