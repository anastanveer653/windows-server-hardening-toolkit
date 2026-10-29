@{
    # Audit subcategories are addressed by GUID so the checks work on every display language.
    Controls = @(
        @{
            Id         = 'LOG-001'
            Title      = 'Advanced audit policy overrides legacy category settings'
            Category   = 'AuditLogging'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'SCENoApplyLegacyAuditPolicy'; ValueType = 'DWord' }
            Expected   = 1
            Rationale  = 'Without this setting, legacy category-level audit policy can silently overwrite the granular subcategory configuration below.'
            References = @{
                Benchmark   = 'CIS: Audit: Force audit policy subcategory settings to override audit policy category settings = Enabled'
                MitreAttack = @('T1562.002')
            }
        }
        @{
            Id         = 'LOG-002'
            Title      = 'Audit Credential Validation'
            Category   = 'AuditLogging'
            Severity   = 'Medium'
            Type       = 'AuditPolicy'
            Target     = @{ Subcategory = 'Credential Validation'; SubcategoryGuid = '{0CCE923F-69AE-11D9-BED3-505054503030}' }
            Expected   = 'SuccessAndFailure'
            Rationale  = 'Records NTLM credential validation (events 4776), the primary signal for password spraying and brute-force attempts.'
            References = @{
                Benchmark   = 'CIS: Audit Credential Validation = Success and Failure'
                MitreAttack = @('T1110')
            }
        }
        @{
            Id         = 'LOG-003'
            Title      = 'Audit Kerberos Authentication Service'
            Category   = 'AuditLogging'
            Severity   = 'Medium'
            Type       = 'AuditPolicy'
            Target     = @{ Subcategory = 'Kerberos Authentication Service'; SubcategoryGuid = '{0CCE9242-69AE-11D9-BED3-505054503030}' }
            Expected   = 'SuccessAndFailure'
            Roles      = @('DomainController')
            Rationale  = 'TGT requests (event 4768/4771) reveal AS-REP roasting, password spraying and unusual encryption types on domain controllers.'
            References = @{
                Benchmark   = 'CIS: Audit Kerberos Authentication Service = Success and Failure (DC only)'
                MitreAttack = @('T1558.004', 'T1110')
            }
        }
        @{
            Id         = 'LOG-004'
            Title      = 'Audit Kerberos Service Ticket Operations'
            Category   = 'AuditLogging'
            Severity   = 'Medium'
            Type       = 'AuditPolicy'
            Target     = @{ Subcategory = 'Kerberos Service Ticket Operations'; SubcategoryGuid = '{0CCE9240-69AE-11D9-BED3-505054503030}' }
            Expected   = 'SuccessAndFailure'
            Roles      = @('DomainController')
            Rationale  = 'Service ticket requests (event 4769) are needed to detect Kerberoasting.'
            References = @{
                Benchmark   = 'CIS: Audit Kerberos Service Ticket Operations = Success and Failure (DC only)'
                MitreAttack = @('T1558.003')
            }
        }
        @{
            Id         = 'LOG-005'
            Title      = 'Audit Security Group Management'
            Category   = 'AuditLogging'
            Severity   = 'Medium'
            Type       = 'AuditPolicy'
            Target     = @{ Subcategory = 'Security Group Management'; SubcategoryGuid = '{0CCE9237-69AE-11D9-BED3-505054503030}' }
            Expected   = 'Success'
            Rationale  = 'Records membership changes of security groups such as local Administrators or Domain Admins.'
            References = @{
                Benchmark   = 'CIS: Audit Security Group Management = include Success'
                MitreAttack = @('T1098')
            }
        }
        @{
            Id         = 'LOG-006'
            Title      = 'Audit User Account Management'
            Category   = 'AuditLogging'
            Severity   = 'Medium'
            Type       = 'AuditPolicy'
            Target     = @{ Subcategory = 'User Account Management'; SubcategoryGuid = '{0CCE9235-69AE-11D9-BED3-505054503030}' }
            Expected   = 'SuccessAndFailure'
            Rationale  = 'Records account creation, deletion, password resets and enabling of accounts, which attackers use for persistence.'
            References = @{
                Benchmark   = 'CIS: Audit User Account Management = Success and Failure'
                MitreAttack = @('T1136', 'T1098')
            }
        }
        @{
            Id         = 'LOG-007'
            Title      = 'Audit Process Creation'
            Category   = 'AuditLogging'
            Severity   = 'Medium'
            Type       = 'AuditPolicy'
            Target     = @{ Subcategory = 'Process Creation'; SubcategoryGuid = '{0CCE922B-69AE-11D9-BED3-505054503030}' }
            Expected   = 'Success'
            Rationale  = 'Process creation events (4688) are the foundation of endpoint detection for malicious execution.'
            Impact     = 'Increases Security log volume; size the log accordingly (see LOG-018).'
            References = @{
                Benchmark   = 'CIS: Audit Process Creation = include Success'
                MitreAttack = @('T1059')
            }
        }
        @{
            Id         = 'LOG-008'
            Title      = 'Audit Account Lockout'
            Category   = 'AuditLogging'
            Severity   = 'Low'
            Type       = 'AuditPolicy'
            Target     = @{ Subcategory = 'Account Lockout'; SubcategoryGuid = '{0CCE9217-69AE-11D9-BED3-505054503030}' }
            Expected   = 'Failure'
            Rationale  = 'Lockout events (4625 with lockout status) help correlate brute-force activity.'
            References = @{
                Benchmark   = 'CIS: Audit Account Lockout = include Failure'
                MitreAttack = @('T1110')
            }
        }
        @{
            Id         = 'LOG-009'
            Title      = 'Audit Logoff'
            Category   = 'AuditLogging'
            Severity   = 'Low'
            Type       = 'AuditPolicy'
            Target     = @{ Subcategory = 'Logoff'; SubcategoryGuid = '{0CCE9216-69AE-11D9-BED3-505054503030}' }
            Expected   = 'Success'
            Rationale  = 'Logoff events complete session timelines during incident investigations.'
            References = @{
                Benchmark   = 'CIS: Audit Logoff = include Success'
                MitreAttack = @('T1078')
            }
        }
        @{
            Id         = 'LOG-010'
            Title      = 'Audit Logon'
            Category   = 'AuditLogging'
            Severity   = 'High'
            Type       = 'AuditPolicy'
            Target     = @{ Subcategory = 'Logon'; SubcategoryGuid = '{0CCE9215-69AE-11D9-BED3-505054503030}' }
            Expected   = 'SuccessAndFailure'
            Rationale  = 'Successful and failed logons (4624/4625) are essential for detecting lateral movement and credential abuse.'
            References = @{
                Benchmark   = 'CIS: Audit Logon = Success and Failure'
                MitreAttack = @('T1078', 'T1021', 'T1110')
            }
        }
        @{
            Id         = 'LOG-011'
            Title      = 'Audit Special Logon'
            Category   = 'AuditLogging'
            Severity   = 'Medium'
            Type       = 'AuditPolicy'
            Target     = @{ Subcategory = 'Special Logon'; SubcategoryGuid = '{0CCE921B-69AE-11D9-BED3-505054503030}' }
            Expected   = 'Success'
            Rationale  = 'Event 4672 flags logons that receive administrative privileges.'
            References = @{
                Benchmark   = 'CIS: Audit Special Logon = include Success'
                MitreAttack = @('T1078')
            }
        }
        @{
            Id         = 'LOG-012'
            Title      = 'Audit Removable Storage'
            Category   = 'AuditLogging'
            Severity   = 'Low'
            Type       = 'AuditPolicy'
            Target     = @{ Subcategory = 'Removable Storage'; SubcategoryGuid = '{0CCE9245-69AE-11D9-BED3-505054503030}' }
            Expected   = 'SuccessAndFailure'
            Rationale  = 'Records file access on removable media for data exfiltration and malware introduction investigations.'
            References = @{
                Benchmark   = 'CIS: Audit Removable Storage = Success and Failure'
                MitreAttack = @('T1052.001', 'T1091')
            }
        }
        @{
            Id         = 'LOG-013'
            Title      = 'Audit Audit Policy Change'
            Category   = 'AuditLogging'
            Severity   = 'High'
            Type       = 'AuditPolicy'
            Target     = @{ Subcategory = 'Audit Policy Change'; SubcategoryGuid = '{0CCE922F-69AE-11D9-BED3-505054503030}' }
            Expected   = 'Success'
            Rationale  = 'Detects attackers disabling auditing to cover their tracks.'
            References = @{
                Benchmark   = 'CIS: Audit Audit Policy Change = include Success'
                MitreAttack = @('T1562.002')
            }
        }
        @{
            Id         = 'LOG-014'
            Title      = 'Audit Authentication Policy Change'
            Category   = 'AuditLogging'
            Severity   = 'Medium'
            Type       = 'AuditPolicy'
            Target     = @{ Subcategory = 'Authentication Policy Change'; SubcategoryGuid = '{0CCE9230-69AE-11D9-BED3-505054503030}' }
            Expected   = 'Success'
            Rationale  = 'Records changes to trusts, Kerberos policy and user rights that weaken authentication.'
            References = @{
                Benchmark   = 'CIS: Audit Authentication Policy Change = include Success'
                MitreAttack = @('T1484')
            }
        }
        @{
            Id         = 'LOG-015'
            Title      = 'Audit Sensitive Privilege Use'
            Category   = 'AuditLogging'
            Severity   = 'Medium'
            Type       = 'AuditPolicy'
            Target     = @{ Subcategory = 'Sensitive Privilege Use'; SubcategoryGuid = '{0CCE9228-69AE-11D9-BED3-505054503030}' }
            Expected   = 'SuccessAndFailure'
            Rationale  = 'Records use of privileges such as SeDebugPrivilege and SeTcbPrivilege that credential theft tools require.'
            References = @{
                Benchmark   = 'CIS: Audit Sensitive Privilege Use = Success and Failure'
                MitreAttack = @('T1134', 'T1003.001')
            }
        }
        @{
            Id         = 'LOG-016'
            Title      = 'Audit Security System Extension'
            Category   = 'AuditLogging'
            Severity   = 'Medium'
            Type       = 'AuditPolicy'
            Target     = @{ Subcategory = 'Security System Extension'; SubcategoryGuid = '{0CCE9211-69AE-11D9-BED3-505054503030}' }
            Expected   = 'Success'
            Rationale  = 'Records loading of authentication packages and service installation (event 4697), common persistence techniques.'
            References = @{
                Benchmark   = 'CIS: Audit Security System Extension = include Success'
                MitreAttack = @('T1543.003', 'T1547.002')
            }
        }
        @{
            Id         = 'LOG-017'
            Title      = 'Audit System Integrity'
            Category   = 'AuditLogging'
            Severity   = 'Medium'
            Type       = 'AuditPolicy'
            Target     = @{ Subcategory = 'System Integrity'; SubcategoryGuid = '{0CCE9212-69AE-11D9-BED3-505054503030}' }
            Expected   = 'SuccessAndFailure'
            Rationale  = 'Records violations of the security subsystem integrity, including audit log tampering and code integrity failures.'
            References = @{
                Benchmark   = 'CIS: Audit System Integrity = Success and Failure'
                MitreAttack = @('T1562.002')
            }
        }
        @{
            Id         = 'LOG-018'
            Title      = 'Security event log maximum size'
            Category   = 'AuditLogging'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name = 'MaxSize'; ValueType = 'DWord' }
            Expected   = 196608
            Operator   = 'GreaterOrEqual'
            Parameter  = 'SecurityLogMaxSizeKB'
            Rationale  = 'A small Security log rolls over quickly and loses the evidence needed to investigate an incident.'
            References = @{
                Benchmark   = 'CIS: Security: Specify the maximum log file size (KB) = 196,608 or greater'
                MitreAttack = @('T1070.001')
            }
        }
        @{
            Id         = 'LOG-019'
            Title      = 'Application event log maximum size'
            Category   = 'AuditLogging'
            Severity   = 'Low'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; Name = 'MaxSize'; ValueType = 'DWord' }
            Expected   = 32768
            Operator   = 'GreaterOrEqual'
            Parameter  = 'ApplicationLogMaxSizeKB'
            Rationale  = 'Keeps enough application history for troubleshooting and investigation.'
            References = @{
                Benchmark   = 'CIS: Application: Specify the maximum log file size (KB) = 32,768 or greater'
                MitreAttack = @('T1070.001')
            }
        }
        @{
            Id         = 'LOG-020'
            Title      = 'System event log maximum size'
            Category   = 'AuditLogging'
            Severity   = 'Low'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'; Name = 'MaxSize'; ValueType = 'DWord' }
            Expected   = 32768
            Operator   = 'GreaterOrEqual'
            Parameter  = 'SystemLogMaxSizeKB'
            Rationale  = 'Keeps enough service and driver history, including service installation events (7045).'
            References = @{
                Benchmark   = 'CIS: System: Specify the maximum log file size (KB) = 32,768 or greater'
                MitreAttack = @('T1070.001')
            }
        }
        @{
            Id         = 'LOG-021'
            Title      = 'Command line is included in process creation events'
            Category   = 'AuditLogging'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; ValueType = 'DWord' }
            Expected   = 1
            MinimumBuild = 9600
            Rationale  = 'Command lines turn process creation events into actionable detections (encoded PowerShell, LOLBins, ransomware tooling).'
            Impact     = 'Command lines can contain secrets passed as arguments; restrict who can read the Security log.'
            References = @{
                Benchmark   = 'CIS: Include command line in process creation events = Enabled'
                MitreAttack = @('T1059', 'T1218')
            }
        }
        @{
            Id         = 'LOG-022'
            Title      = 'PowerShell script block logging is enabled'
            Category   = 'AuditLogging'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; ValueType = 'DWord' }
            Expected   = 1
            Rationale  = 'Logs the de-obfuscated content of executed PowerShell (event 4104), defeating most encoding tricks used by attackers.'
            Impact     = 'Increases the size of the PowerShell Operational log.'
            References = @{
                Benchmark   = 'CIS: Turn on PowerShell Script Block Logging = Enabled'
                MitreAttack = @('T1059.001')
            }
        }
    )
}
