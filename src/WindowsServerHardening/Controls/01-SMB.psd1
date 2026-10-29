@{
    Controls = @(
        @{
            Id         = 'SMB-001'
            Title      = 'SMBv1 server protocol is disabled'
            Category   = 'SMB'
            Severity   = 'Critical'
            Type       = 'SmbServer'
            Target     = @{ Property = 'EnableSMB1Protocol' }
            Expected   = $false
            Rationale  = 'SMBv1 lacks pre-authentication integrity and encryption and was the attack surface for EternalBlue (MS17-010), used by WannaCry and NotPetya.'
            Impact     = 'Clients that only speak SMBv1 (Windows XP / Server 2003, old NAS and printers) can no longer connect to this server.'
            References = @{
                Benchmark   = 'CIS: Configure SMB v1 server = Disabled'
                MitreAttack = @('T1210')
                Links       = @('https://learn.microsoft.com/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3')
            }
        }
        @{
            Id         = 'SMB-002'
            Title      = 'SMBv1 client driver is disabled'
            Category   = 'SMB'
            Severity   = 'High'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'; Name = 'Start'; ValueType = 'DWord'; SkipIfKeyMissing = $true }
            Expected   = 4
            RebootRequired = $true
            Rationale  = 'The SMBv1 client driver lets this server connect to legacy SMBv1 shares and exposes it to the same protocol weaknesses as the SMBv1 server.'
            Impact     = 'The server can no longer access file shares that only support SMBv1.'
            References = @{
                Benchmark   = 'CIS: Configure SMB v1 client driver = Enabled: Disable driver'
                MitreAttack = @('T1210')
            }
        }
        @{
            Id         = 'SMB-003'
            Title      = 'SMB server requires packet signing'
            Category   = 'SMB'
            Severity   = 'High'
            Type       = 'SmbServer'
            Target     = @{ Property = 'RequireSecuritySignature' }
            Expected   = $true
            Rationale  = 'Without mandatory signing, captured NTLM authentications can be relayed to this server (SMB relay) and SMB traffic can be tampered with in transit.'
            Impact     = 'Small throughput cost on very high-volume file servers; all supported Windows clients support signing.'
            References = @{
                Benchmark   = 'CIS: Microsoft network server: Digitally sign communications (always) = Enabled'
                MitreAttack = @('T1557.001')
            }
        }
        @{
            Id         = 'SMB-004'
            Title      = 'SMB client requires packet signing'
            Category   = 'SMB'
            Severity   = 'High'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name = 'RequireSecuritySignature'; ValueType = 'DWord' }
            Expected   = 1
            Rationale  = 'Requiring signing on outbound SMB sessions prevents attackers from impersonating file servers or modifying data this server reads, such as scripts on SYSVOL.'
            Impact     = 'The server cannot connect to SMB servers that do not support signing.'
            References = @{
                Benchmark   = 'CIS: Microsoft network client: Digitally sign communications (always) = Enabled'
                MitreAttack = @('T1557.001')
            }
        }
        @{
            Id         = 'SMB-005'
            Title      = 'SMB server encrypts data in transit'
            Category   = 'SMB'
            Severity   = 'Medium'
            Type       = 'SmbServer'
            Target     = @{ Property = 'EncryptData' }
            Expected   = $true
            Rationale  = 'SMB 3 encryption protects file contents and credentials-derived data on the wire against sniffing on untrusted network segments.'
            Impact     = 'Clients that do not support SMB 3.0 (Windows 7 / Server 2008 R2 and older) are refused access. Exclude this control if such clients must connect.'
            References = @{
                Benchmark   = 'Microsoft guidance: SMB security enhancements (SMB encryption)'
                MitreAttack = @('T1040', 'T1557')
            }
        }
        @{
            Id         = 'SMB-006'
            Title      = 'Anonymous access to named pipes and shares is restricted'
            Category   = 'SMB'
            Severity   = 'High'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'RestrictNullSessAccess'; ValueType = 'DWord'; AbsentValue = 1 }
            Expected   = 1
            Rationale  = 'Null sessions let unauthenticated users enumerate shares and pipes and gather reconnaissance information about the server and domain.'
            References = @{
                Benchmark   = 'CIS: Network access: Restrict anonymous access to Named Pipes and Shares = Enabled'
                MitreAttack = @('T1135', 'T1087')
            }
        }
        @{
            Id         = 'SMB-007'
            Title      = 'Insecure guest logons to SMB servers are disabled'
            Category   = 'SMB'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; Name = 'AllowInsecureGuestAuth'; ValueType = 'DWord' }
            Expected   = 0
            MinimumBuild = 14393
            Rationale  = 'Guest (unauthenticated) SMB access disables signing and encryption and makes the server trust rogue file servers.'
            References = @{
                Benchmark   = 'CIS: Enable insecure guest logons = Disabled'
                MitreAttack = @('T1557')
            }
        }
    )
}
