@{
    # Services that are not installed are reported as NotApplicable rather than skipped silently.
    Controls = @(
        @{
            Id         = 'SVC-001'
            Title      = 'Print Spooler service is disabled'
            Category   = 'Services'
            Severity   = 'High'
            Type       = 'Service'
            Target     = @{ Name = 'Spooler' }
            Expected   = 'Disabled'
            Rationale  = 'The Print Spooler has a long history of critical vulnerabilities (PrintNightmare CVE-2021-34527) and enables coercion attacks such as PrinterBug.'
            Impact     = 'The server can no longer share or print. Exclude this control on print servers and servers that need to print.'
            References = @{
                Benchmark   = 'CIS: Print Spooler (Spooler) = Disabled (required on domain controllers)'
                MitreAttack = @('T1068', 'T1187', 'T1210')
            }
        }
        @{
            Id         = 'SVC-002'
            Title      = 'Remote Registry service is disabled'
            Category   = 'Services'
            Severity   = 'Medium'
            Type       = 'Service'
            Target     = @{ Name = 'RemoteRegistry' }
            Expected   = 'Disabled'
            Rationale  = 'Remote Registry lets remote users read and modify the registry, which is used for reconnaissance and lateral movement.'
            Impact     = 'Some legacy monitoring and inventory tools that read the registry remotely stop working.'
            References = @{
                Benchmark   = 'CIS: Remote Registry (RemoteRegistry) = Disabled'
                MitreAttack = @('T1012', 'T1112')
            }
        }
        @{
            Id         = 'SVC-003'
            Title      = 'Telnet server is disabled'
            Category   = 'Services'
            Severity   = 'High'
            Type       = 'Service'
            Target     = @{ Name = 'TlntSvr' }
            Expected   = 'Disabled'
            Rationale  = 'Telnet provides remote shell access with cleartext credentials.'
            References = @{
                Benchmark   = 'Hardening best practice: remove cleartext remote shells'
                MitreAttack = @('T1021', 'T1040')
            }
        }
        @{
            Id         = 'SVC-004'
            Title      = 'SNMP service is disabled'
            Category   = 'Services'
            Severity   = 'Medium'
            Type       = 'Service'
            Target     = @{ Name = 'SNMP' }
            Expected   = 'Disabled'
            Rationale  = 'SNMP v1/v2c uses cleartext community strings and leaks detailed system and network information.'
            Impact     = 'Monitoring systems that poll SNMP stop receiving data; prefer WMI/WinRM or SNMPv3 agents.'
            References = @{
                Benchmark   = 'CIS: SNMP Service (SNMP) = Disabled or Not Installed'
                MitreAttack = @('T1046', 'T1602.001')
            }
        }
        @{
            Id         = 'SVC-005'
            Title      = 'Simple TCP/IP Services are disabled'
            Category   = 'Services'
            Severity   = 'Low'
            Type       = 'Service'
            Target     = @{ Name = 'simptcp' }
            Expected   = 'Disabled'
            Rationale  = 'Echo, discard, chargen and similar legacy services have no business use and can be abused for amplification.'
            References = @{
                Benchmark   = 'CIS: Simple TCP/IP Services (simptcp) = Disabled or Not Installed'
                MitreAttack = @('T1046')
            }
        }
        @{
            Id         = 'SVC-006'
            Title      = 'Remote Access Auto Connection Manager is disabled'
            Category   = 'Services'
            Severity   = 'Low'
            Type       = 'Service'
            Target     = @{ Name = 'RasAuto' }
            Expected   = 'Disabled'
            Rationale  = 'Automatically dialing remote networks is not required on servers and increases attack surface.'
            References = @{
                Benchmark   = 'Microsoft guidance: disabling system services on Windows Server with Desktop Experience'
            }
        }
        @{
            Id         = 'SVC-007'
            Title      = 'SSDP Discovery service is disabled'
            Category   = 'Services'
            Severity   = 'Low'
            Type       = 'Service'
            Target     = @{ Name = 'SSDPSRV' }
            Expected   = 'Disabled'
            Rationale  = 'SSDP/UPnP discovery is a consumer feature that exposes the host to network discovery and UPnP attacks.'
            References = @{
                Benchmark   = 'Microsoft guidance: disabling system services on Windows Server with Desktop Experience'
                MitreAttack = @('T1046')
            }
        }
        @{
            Id         = 'SVC-008'
            Title      = 'UPnP Device Host service is disabled'
            Category   = 'Services'
            Severity   = 'Low'
            Type       = 'Service'
            Target     = @{ Name = 'upnphost' }
            Expected   = 'Disabled'
            Rationale  = 'Hosting UPnP devices is not a server workload and adds unauthenticated network attack surface.'
            References = @{
                Benchmark   = 'Microsoft guidance: disabling system services on Windows Server with Desktop Experience'
                MitreAttack = @('T1046')
            }
        }
        @{
            Id         = 'SVC-009'
            Title      = 'Xbox Live Auth Manager service is disabled'
            Category   = 'Services'
            Severity   = 'Low'
            Type       = 'Service'
            Target     = @{ Name = 'XblAuthManager' }
            Expected   = 'Disabled'
            Rationale  = 'Consumer gaming services have no place on a server and only add attack surface.'
            References = @{ Benchmark = 'Microsoft guidance: disabling system services on Windows Server with Desktop Experience' }
        }
        @{
            Id         = 'SVC-010'
            Title      = 'Xbox Live Game Save service is disabled'
            Category   = 'Services'
            Severity   = 'Low'
            Type       = 'Service'
            Target     = @{ Name = 'XblGameSave' }
            Expected   = 'Disabled'
            Rationale  = 'Consumer gaming services have no place on a server and only add attack surface.'
            References = @{ Benchmark = 'Microsoft guidance: disabling system services on Windows Server with Desktop Experience' }
        }
        @{
            Id         = 'SVC-011'
            Title      = 'Geolocation service is disabled'
            Category   = 'Services'
            Severity   = 'Low'
            Type       = 'Service'
            Target     = @{ Name = 'lfsvc' }
            Expected   = 'Disabled'
            Rationale  = 'Location tracking is not needed on servers.'
            References = @{ Benchmark = 'Microsoft guidance: disabling system services on Windows Server with Desktop Experience' }
        }
        @{
            Id         = 'SVC-012'
            Title      = 'Downloaded Maps Manager service is disabled'
            Category   = 'Services'
            Severity   = 'Low'
            Type       = 'Service'
            Target     = @{ Name = 'MapsBroker' }
            Expected   = 'Disabled'
            Rationale  = 'Offline maps are a client feature that is not needed on servers.'
            References = @{ Benchmark = 'Microsoft guidance: disabling system services on Windows Server with Desktop Experience' }
        }
        @{
            Id         = 'SVC-013'
            Title      = 'Windows Mobile Hotspot service is disabled'
            Category   = 'Services'
            Severity   = 'Medium'
            Type       = 'Service'
            Target     = @{ Name = 'icssvc' }
            Expected   = 'Disabled'
            Rationale  = 'A mobile hotspot could bridge the server network to an uncontrolled wireless network.'
            References = @{
                Benchmark   = 'Microsoft guidance: disabling system services on Windows Server with Desktop Experience'
                MitreAttack = @('T1133')
            }
        }
        @{
            Id         = 'SVC-014'
            Title      = 'Remote Procedure Call Locator is disabled'
            Category   = 'Services'
            Severity   = 'Low'
            Type       = 'Service'
            Target     = @{ Name = 'RpcLocator' }
            Expected   = 'Disabled'
            Rationale  = 'The legacy RPC name service is only needed by very old applications.'
            References = @{ Benchmark = 'Microsoft guidance: disabling system services on Windows Server with Desktop Experience' }
        }
    )
}
