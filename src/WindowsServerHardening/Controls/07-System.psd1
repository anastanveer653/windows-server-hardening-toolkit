@{
    Controls = @(
        @{
            Id         = 'SYS-001'
            Title      = 'User Account Control is enabled (Admin Approval Mode)'
            Category   = 'System'
            Severity   = 'High'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableLUA'; ValueType = 'DWord'; AbsentValue = 1 }
            Expected   = 1
            RebootRequired = $true
            Rationale  = 'With UAC disabled every administrator process runs with a full token, removing a key barrier against malware.'
            References = @{
                Benchmark   = 'CIS: User Account Control: Run all administrators in Admin Approval Mode = Enabled'
                MitreAttack = @('T1548.002')
            }
        }
        @{
            Id         = 'SYS-002'
            Title      = 'Admin Approval Mode applies to the built-in Administrator'
            Category   = 'System'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'FilterAdministratorToken'; ValueType = 'DWord'; AbsentValue = 0 }
            Expected   = 1
            Rationale  = 'Without this, the built-in Administrator account always runs elevated and bypasses UAC entirely.'
            Impact     = 'The built-in Administrator receives elevation prompts like other administrators.'
            References = @{
                Benchmark   = 'CIS: User Account Control: Admin Approval Mode for the Built-in Administrator account = Enabled'
                MitreAttack = @('T1548.002')
            }
        }
        @{
            Id         = 'SYS-003'
            Title      = 'Elevation prompt for administrators uses the secure desktop'
            Category   = 'System'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ConsentPromptBehaviorAdmin'; ValueType = 'DWord'; AbsentValue = 5 }
            Expected   = 2
            Operator   = 'In'
            Allowed    = @(1, 2)
            Rationale  = 'Prompting on the secure desktop prevents other processes from spoofing or auto-approving the elevation dialog.'
            References = @{
                Benchmark   = 'CIS: User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode = Prompt for consent on the secure desktop'
                MitreAttack = @('T1548.002')
            }
        }
        @{
            Id           = 'SYS-004'
            Title        = 'UAC restrictions apply to local accounts on network logons'
            Category     = 'System'
            Severity     = 'High'
            Type         = 'Registry'
            Target       = @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'LocalAccountTokenFilterPolicy'; ValueType = 'DWord'; AbsentValue = 0 }
            Expected     = 0
            ExcludeRoles = @('DomainController')
            Rationale    = 'Filtering the token of local administrators on network logons blocks pass-the-hash with local Administrator accounts.'
            Impact       = 'Remote administration with local (non-domain) administrator accounts no longer receives full rights; use domain accounts or LAPS.'
            References   = @{
                Benchmark   = 'CIS: Apply UAC restrictions to local accounts on network logons = Enabled (member servers)'
                MitreAttack = @('T1550.002', 'T1021.002')
            }
        }
        @{
            Id         = 'SYS-005'
            Title      = 'AutoPlay is turned off for all drives'
            Category   = 'System'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoDriveTypeAutoRun'; ValueType = 'DWord' }
            Expected   = 255
            Rationale  = 'AutoPlay can launch content from removable or network media without user intent.'
            References = @{
                Benchmark   = 'CIS: Turn off Autoplay = Enabled: All drives'
                MitreAttack = @('T1091')
            }
        }
        @{
            Id         = 'SYS-006'
            Title      = 'AutoRun commands are not executed'
            Category   = 'System'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoAutorun'; ValueType = 'DWord' }
            Expected   = 1
            Rationale  = 'Blocks autorun.inf commands, a classic malware propagation method through USB devices.'
            References = @{
                Benchmark   = 'CIS: Set the default behavior for AutoRun = Enabled: Do not execute any autorun commands'
                MitreAttack = @('T1091')
            }
        }
        @{
            Id         = 'SYS-007'
            Title      = 'Last signed-in user name is not displayed'
            Category   = 'System'
            Severity   = 'Low'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'DontDisplayLastUserName'; ValueType = 'DWord' }
            Expected   = 1
            Rationale  = 'Showing the last user name on the logon screen discloses valid (often administrative) account names.'
            References = @{
                Benchmark   = 'CIS: Interactive logon: Do not display last signed-in = Enabled'
                MitreAttack = @('T1087')
            }
        }
        @{
            Id         = 'SYS-008'
            Title      = 'Machine inactivity limit locks idle sessions'
            Category   = 'System'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'InactivityTimeoutSecs'; ValueType = 'DWord' }
            Expected   = 900
            Operator   = 'Range'
            Minimum    = 1
            Parameter  = 'InactivityTimeoutSeconds'
            Rationale  = 'Unattended unlocked console and RDP sessions give anyone with physical or session access full control.'
            References = @{
                Benchmark   = 'CIS: Interactive logon: Machine inactivity limit = 900 or fewer second(s), but not 0'
                MitreAttack = @('T1078')
            }
        }
        @{
            Id         = 'SYS-009'
            Title      = 'Logon banner title is configured'
            Category   = 'System'
            Severity   = 'Low'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'LegalNoticeCaption'; ValueType = 'String' }
            Expected   = 'Authorized use only'
            Parameter  = 'LegalNoticeCaption'
            Rationale  = 'A legal notice establishes that access is monitored and supports prosecution of unauthorized use.'
            References = @{ Benchmark = 'CIS: Interactive logon: Message title for users attempting to log on = configured' }
        }
        @{
            Id         = 'SYS-010'
            Title      = 'Logon banner text is configured'
            Category   = 'System'
            Severity   = 'Low'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'LegalNoticeText'; ValueType = 'String' }
            Expected   = 'This system is for authorized use only. All activity is monitored and logged.'
            Parameter  = 'LegalNoticeText'
            Rationale  = 'A legal notice establishes that access is monitored and supports prosecution of unauthorized use.'
            References = @{ Benchmark = 'CIS: Interactive logon: Message text for users attempting to log on = configured' }
        }
        @{
            Id         = 'SYS-011'
            Title      = 'Structured Exception Handling Overwrite Protection (SEHOP) is enabled'
            Category   = 'System'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'; Name = 'DisableExceptionChainValidation'; ValueType = 'DWord' }
            Expected   = 0
            RebootRequired = $true
            Rationale  = 'SEHOP blocks a widely used class of stack-based exploitation techniques.'
            References = @{
                Benchmark   = 'CIS: Enable Structured Exception Handling Overwrite Protection (SEHOP) = Enabled'
                MitreAttack = @('T1203', 'T1068')
            }
        }
        @{
            Id         = 'SYS-012'
            Title      = 'Data Execution Prevention covers all processes'
            Category   = 'System'
            Severity   = 'Medium'
            Type       = 'Custom'
            Target     = @{ Check = 'DepPolicy'; ManualRemediation = 'Run "bcdedit /set {current} nx OptOut" (or AlwaysOn) from an elevated prompt and restart.' }
            Expected   = 3
            Operator   = 'In'
            Allowed    = @(1, 3)
            Rationale  = 'DEP in OptOut or AlwaysOn mode prevents code execution from data pages for every process, not only for Windows components.'
            References = @{
                Benchmark   = 'Microsoft guidance: Data Execution Prevention'
                MitreAttack = @('T1203', 'T1068')
            }
        }
        @{
            Id         = 'SYS-013'
            Title      = 'UEFI Secure Boot is enabled'
            Category   = 'System'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'; Name = 'UEFISecureBootEnabled'; ValueType = 'DWord'; ManualRemediation = 'Enable Secure Boot in the UEFI firmware (or the VM settings) and restart. Legacy BIOS installations must be converted to UEFI first (mbr2gpt).' }
            Expected   = 1
            AuditOnly  = $true
            Rationale  = 'Secure Boot ensures only signed boot loaders run, protecting against bootkits, and is a prerequisite for Credential Guard.'
            References = @{
                Benchmark   = 'Microsoft guidance: Secure the Windows boot process'
                MitreAttack = @('T1542.003')
            }
        }
        @{
            Id         = 'SYS-014'
            Title      = 'Windows Script Host is disabled'
            Category   = 'System'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'; Name = 'Enabled'; ValueType = 'DWord' }
            Expected   = 0
            OptIn      = $true
            Rationale  = 'Blocks VBScript and JScript droppers executed through wscript.exe and cscript.exe.'
            Impact     = 'Opt-in: breaks VBScript logon scripts, some installers and management agents that rely on WSH. Enable via the profile EnableControls list after testing.'
            References = @{
                Benchmark   = 'Hardening best practice: disable unused script interpreters'
                MitreAttack = @('T1059.005', 'T1059.007')
            }
        }
    )
}
