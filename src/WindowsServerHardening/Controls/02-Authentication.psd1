@{
    Controls = @(
        @{
            Id         = 'AUTH-001'
            Title      = 'LAN Manager authentication level is NTLMv2 only'
            Category   = 'Authentication'
            Severity   = 'Critical'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LmCompatibilityLevel'; ValueType = 'DWord'; AbsentValue = 3 }
            Expected   = 5
            Rationale  = 'Levels below 5 accept LM and NTLMv1 responses, which can be cracked or downgraded and relayed in minutes.'
            Impact     = 'Legacy systems and appliances that only support LM/NTLMv1 can no longer authenticate.'
            References = @{
                Benchmark   = 'CIS: Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM'
                MitreAttack = @('T1557.001', 'T1550.002', 'T1110.002')
            }
        }
        @{
            Id         = 'AUTH-002'
            Title      = 'LAN Manager password hashes are not stored'
            Category   = 'Authentication'
            Severity   = 'High'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'NoLMHash'; ValueType = 'DWord'; AbsentValue = 1 }
            Expected   = 1
            Rationale  = 'LM hashes are trivially reversible; storing them in the SAM gives an attacker with SAM access the cleartext passwords.'
            References = @{
                Benchmark   = 'CIS: Network security: Do not store LAN Manager hash value on next password change = Enabled'
                MitreAttack = @('T1003.002', 'T1110.002')
            }
        }
        @{
            Id         = 'AUTH-003'
            Title      = 'WDigest does not cache cleartext credentials'
            Category   = 'Authentication'
            Severity   = 'Critical'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name = 'UseLogonCredential'; ValueType = 'DWord'; AbsentValue = 0; AbsentValueMinimumBuild = 9600 }
            Expected   = 0
            Rationale  = 'When enabled, WDigest keeps plaintext passwords in LSASS memory where tools such as Mimikatz can read them. It is off by default from Windows Server 2012 R2; on Windows Server 2012 it must be disabled explicitly (KB2871997).'
            References = @{
                Benchmark   = 'CIS: WDigest Authentication = Disabled'
                MitreAttack = @('T1003.001')
            }
        }
        @{
            Id         = 'AUTH-004'
            Title      = 'LSASS runs as a protected process (RunAsPPL)'
            Category   = 'Authentication'
            Severity   = 'High'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RunAsPPL'; ValueType = 'DWord' }
            Expected   = 1
            Operator   = 'In'
            Allowed    = @(1, 2)
            MinimumBuild = 9600
            RebootRequired = $true
            Rationale  = 'LSA protection blocks non-protected processes, including most credential dumping tools, from reading LSASS memory or injecting code into it. Value 1 enables it with a UEFI lock, value 2 (Windows 11 22H2 / Server 2025 and later) without.'
            Impact     = 'Third-party LSA plug-ins and smart card drivers that are not signed for protected processes stop loading. Test with the CodeIntegrity event log first.'
            References = @{
                Benchmark   = 'CIS: Configure LSASS to run as a protected process = Enabled'
                MitreAttack = @('T1003.001')
                Links       = @('https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection')
            }
        }
        @{
            Id         = 'AUTH-005'
            Title      = 'NTLM SSP server sessions require NTLMv2 and 128-bit encryption'
            Category   = 'Authentication'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'NTLMMinServerSec'; ValueType = 'DWord' }
            Expected   = 537395200
            Rationale  = 'Requiring NTLMv2 session security and 128-bit encryption prevents downgrade to weak NTLM session keys.'
            References = @{
                Benchmark   = 'CIS: Network security: Minimum session security for NTLM SSP based (including secure RPC) servers = Require NTLMv2 session security, Require 128-bit encryption'
                MitreAttack = @('T1557')
            }
        }
        @{
            Id         = 'AUTH-006'
            Title      = 'NTLM SSP client sessions require NTLMv2 and 128-bit encryption'
            Category   = 'Authentication'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'NTLMMinClientSec'; ValueType = 'DWord' }
            Expected   = 537395200
            Rationale  = 'Ensures outbound NTLM sessions from this server cannot be negotiated down to weak session security.'
            References = @{
                Benchmark   = 'CIS: Network security: Minimum session security for NTLM SSP based (including secure RPC) clients = Require NTLMv2 session security, Require 128-bit encryption'
                MitreAttack = @('T1557')
            }
        }
        @{
            Id         = 'AUTH-007'
            Title      = 'Local accounts with blank passwords are limited to console logon'
            Category   = 'Authentication'
            Severity   = 'High'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'LimitBlankPasswordUse'; ValueType = 'DWord'; AbsentValue = 1 }
            Expected   = 1
            Rationale  = 'Prevents network logons (SMB, RDP, WinRM) with local accounts that have an empty password.'
            References = @{
                Benchmark   = 'CIS: Accounts: Limit local account use of blank passwords to console logon only = Enabled'
                MitreAttack = @('T1078.003')
            }
        }
        @{
            Id         = 'AUTH-008'
            Title      = 'CredSSP encryption oracle remediation is set to Force Updated Clients'
            Category   = 'Authentication'
            Severity   = 'High'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'; Name = 'AllowEncryptionOracle'; ValueType = 'DWord' }
            Expected   = 0
            Rationale  = 'Mitigates CVE-2018-0886, a CredSSP flaw that allows remote code execution through a man-in-the-middle position during RDP or WinRM authentication.'
            Impact     = 'Unpatched RDP clients or servers can no longer establish CredSSP sessions with this server.'
            References = @{
                Benchmark   = 'CIS: Encryption Oracle Remediation = Enabled: Force Updated Clients'
                MitreAttack = @('T1557', 'T1210')
            }
        }
        @{
            Id         = 'AUTH-009'
            Title      = 'Anonymous SID/name translation is disabled'
            Category   = 'Authentication'
            Severity   = 'Medium'
            Type       = 'SecurityPolicy'
            Target     = @{ Section = 'System Access'; Key = 'LSAAnonymousNameLookup' }
            Expected   = 0
            Rationale  = 'Anonymous SID-to-name lookups allow unauthenticated users to resolve the built-in Administrator account name even when it was renamed.'
            References = @{
                Benchmark   = 'CIS: Network access: Allow anonymous SID/Name translation = Disabled'
                MitreAttack = @('T1087')
            }
        }
        @{
            Id         = 'AUTH-010'
            Title      = 'Anonymous enumeration of SAM accounts is not allowed'
            Category   = 'Authentication'
            Severity   = 'High'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymousSAM'; ValueType = 'DWord'; AbsentValue = 1 }
            Expected   = 1
            Rationale  = 'Blocks unauthenticated users from listing local and domain accounts, a common first step in password spraying.'
            References = @{
                Benchmark   = 'CIS: Network access: Do not allow anonymous enumeration of SAM accounts = Enabled'
                MitreAttack = @('T1087.001', 'T1087.002', 'T1110.003')
            }
        }
        @{
            Id         = 'AUTH-011'
            Title      = 'Anonymous enumeration of SAM accounts and shares is not allowed'
            Category   = 'Authentication'
            Severity   = 'High'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous'; ValueType = 'DWord' }
            Expected   = 1
            Rationale  = 'Prevents anonymous users from enumerating account names and network shares.'
            Impact     = 'Very old applications that rely on anonymous enumeration (for example NT4-era trusts) stop working.'
            References = @{
                Benchmark   = 'CIS: Network access: Do not allow anonymous enumeration of SAM accounts and shares = Enabled'
                MitreAttack = @('T1087', 'T1135')
            }
        }
        @{
            Id         = 'AUTH-012'
            Title      = 'Everyone permissions do not apply to anonymous users'
            Category   = 'Authentication'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'EveryoneIncludesAnonymous'; ValueType = 'DWord'; AbsentValue = 0 }
            Expected   = 0
            Rationale  = 'Keeps anonymous users from inheriting access granted to the Everyone group on files, shares and registry keys.'
            References = @{
                Benchmark   = 'CIS: Network access: Let Everyone permissions apply to anonymous users = Disabled'
                MitreAttack = @('T1135')
            }
        }
        @{
            Id           = 'AUTH-013'
            Title        = 'Credential Guard is running'
            Category     = 'Authentication'
            Severity     = 'High'
            Type         = 'Custom'
            Target       = @{ Check = 'CredentialGuard'; ManualRemediation = 'Enable virtualization-based security with Credential Guard (UEFI lock) through Group Policy or Intune; requires UEFI, Secure Boot and a TPM.' }
            Expected     = 'Running'
            ExcludeRoles = @('DomainController')
            MinimumBuild = 14393
            Rationale    = 'Credential Guard isolates NTLM hashes and Kerberos tickets in a virtualization-based enclave so they cannot be dumped from LSASS, even by an administrator.'
            Impact       = 'Not supported on domain controllers; breaks NTLMv1, MS-CHAPv2 and unconstrained Kerberos delegation on the protected host.'
            References   = @{
                Benchmark   = 'CIS: Turn On Virtualization Based Security: Credential Guard Configuration = Enabled with UEFI lock'
                MitreAttack = @('T1003.001', 'T1550.002', 'T1558')
            }
        }
    )
}
