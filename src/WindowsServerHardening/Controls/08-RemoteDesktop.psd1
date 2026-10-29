@{
    Controls = @(
        @{
            Id         = 'RDP-001'
            Title      = 'Network Level Authentication is required for RDP'
            Category   = 'RemoteDesktop'
            Severity   = 'High'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'UserAuthentication'; ValueType = 'DWord' }
            Expected   = 1
            Rationale  = 'NLA authenticates users before a full RDP session is created, shielding the server from pre-authentication exploits such as BlueKeep (CVE-2019-0708) and resource exhaustion.'
            References = @{
                Benchmark   = 'CIS: Require user authentication for remote connections by using Network Level Authentication = Enabled'
                MitreAttack = @('T1021.001', 'T1210')
            }
        }
        @{
            Id         = 'RDP-002'
            Title      = 'RDP security layer is TLS'
            Category   = 'RemoteDesktop'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'SecurityLayer'; ValueType = 'DWord' }
            Expected   = 2
            Rationale  = 'The native RDP security layer does not authenticate the server, allowing man-in-the-middle interception.'
            References = @{
                Benchmark   = 'CIS: Require use of specific security layer for remote (RDP) connections = SSL'
                MitreAttack = @('T1557')
            }
        }
        @{
            Id         = 'RDP-003'
            Title      = 'RDP client connection encryption level is High'
            Category   = 'RemoteDesktop'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'MinEncryptionLevel'; ValueType = 'DWord' }
            Expected   = 3
            Rationale  = 'Requires 128-bit encryption for RDP sessions that do not use TLS.'
            References = @{
                Benchmark   = 'CIS: Set client connection encryption level = High Level'
                MitreAttack = @('T1040')
            }
        }
        @{
            Id         = 'RDP-004'
            Title      = 'RDP always prompts for a password'
            Category   = 'RemoteDesktop'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fPromptForPassword'; ValueType = 'DWord' }
            Expected   = 1
            Rationale  = 'Prevents RDP connections that reuse credentials stored in an attacker-controlled .rdp file or client.'
            References = @{
                Benchmark   = 'CIS: Always prompt for password upon connection = Enabled'
                MitreAttack = @('T1021.001', 'T1078')
            }
        }
        @{
            Id         = 'RDP-005'
            Title      = 'RDP clients cannot save passwords'
            Category   = 'RemoteDesktop'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'DisablePasswordSaving'; ValueType = 'DWord' }
            Expected   = 1
            Rationale  = 'Saved RDP credentials in Credential Manager are a common target for credential harvesting.'
            References = @{
                Benchmark   = 'CIS: Do not allow passwords to be saved = Enabled'
                MitreAttack = @('T1555.004')
            }
        }
        @{
            Id         = 'RDP-006'
            Title      = 'RDP drive redirection is disabled'
            Category   = 'RemoteDesktop'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fDisableCdm'; ValueType = 'DWord' }
            Expected   = 1
            Rationale  = 'Mapped client drives provide an easy path to copy tools onto the server and exfiltrate data.'
            Impact     = 'Administrators can no longer copy files through mapped drives in RDP sessions.'
            References = @{
                Benchmark   = 'CIS: Do not allow drive redirection = Enabled'
                MitreAttack = @('T1105', 'T1048')
            }
        }
        @{
            Id         = 'RDP-007'
            Title      = 'RDP clipboard redirection is disabled'
            Category   = 'RemoteDesktop'
            Severity   = 'Low'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = 'fDisableClip'; ValueType = 'DWord' }
            Expected   = 1
            OptIn      = $true
            Rationale  = 'Clipboard redirection can leak data out of, or move payloads into, the server.'
            Impact     = 'Opt-in: copy and paste between the admin workstation and the server stops working.'
            References = @{
                Benchmark   = 'CIS (Level 2): Do not allow Clipboard redirection = Enabled'
                MitreAttack = @('T1115')
            }
        }
    )
}
