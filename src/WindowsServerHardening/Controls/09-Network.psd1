@{
    Controls = @(
        @{
            Id         = 'NET-001'
            Title      = 'LLMNR (multicast name resolution) is disabled'
            Category   = 'Network'
            Severity   = 'High'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name = 'EnableMulticast'; ValueType = 'DWord' }
            Expected   = 0
            Rationale  = 'LLMNR responses can be spoofed by any host on the subnet to capture NTLM hashes (Responder-style attacks).'
            References = @{
                Benchmark   = 'CIS: Turn off multicast name resolution = Enabled'
                MitreAttack = @('T1557.001')
            }
        }
        @{
            Id         = 'NET-002'
            Title      = 'NetBIOS name resolution uses P-node (no broadcasts)'
            Category   = 'Network'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'; Name = 'NodeType'; ValueType = 'DWord' }
            Expected   = 2
            RebootRequired = $true
            Rationale  = 'P-node stops NetBIOS broadcast name queries, which are poisoned in the same way as LLMNR.'
            Impact     = 'NetBIOS names are then resolved only through WINS; environments that rely on broadcast resolution must use DNS.'
            References = @{
                Benchmark   = 'CIS: NetBT NodeType configuration = P-node'
                MitreAttack = @('T1557.001')
            }
        }
        @{
            Id         = 'NET-003'
            Title      = 'IP source routing is disabled'
            Category   = 'Network'
            Severity   = 'Low'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'DisableIPSourceRouting'; ValueType = 'DWord' }
            Expected   = 2
            Rationale  = 'Source-routed packets let an attacker dictate the network path and bypass filtering.'
            References = @{ Benchmark = 'CIS: MSS: (DisableIPSourceRouting) IP source routing protection level = Highest protection, source routing is completely disabled' }
        }
        @{
            Id         = 'NET-004'
            Title      = 'ICMP redirects cannot override routes'
            Category   = 'Network'
            Severity   = 'Low'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name = 'EnableICMPRedirect'; ValueType = 'DWord' }
            Expected   = 0
            Rationale  = 'Forged ICMP redirects can reroute server traffic through an attacker-controlled host.'
            References = @{
                Benchmark   = 'CIS: MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes = Disabled'
                MitreAttack = @('T1557')
            }
        }
        @{
            Id         = 'NET-005'
            Title      = 'SSL 2.0 is disabled for server connections'
            Category   = 'Network'
            Severity   = 'High'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server'; Name = 'Enabled'; ValueType = 'DWord' }
            Expected   = 0
            RebootRequired = $true
            Rationale  = 'SSL 2.0 is fundamentally broken and must never be negotiated.'
            References = @{
                Benchmark   = 'Microsoft guidance: TLS/SSL settings (SCHANNEL protocols)'
                MitreAttack = @('T1557', 'T1040')
            }
        }
        @{
            Id         = 'NET-006'
            Title      = 'SSL 3.0 is disabled for server connections'
            Category   = 'Network'
            Severity   = 'High'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server'; Name = 'Enabled'; ValueType = 'DWord' }
            Expected   = 0
            RebootRequired = $true
            Rationale  = 'SSL 3.0 is vulnerable to POODLE and must not be offered by servers.'
            References = @{
                Benchmark   = 'Microsoft guidance: TLS/SSL settings (SCHANNEL protocols)'
                MitreAttack = @('T1557', 'T1040')
            }
        }
        @{
            Id         = 'NET-007'
            Title      = 'TLS 1.0 is disabled for server connections'
            Category   = 'Network'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'; Name = 'Enabled'; ValueType = 'DWord' }
            Expected   = 0
            OptIn      = $true
            RebootRequired = $true
            Rationale  = 'TLS 1.0 relies on deprecated cryptography and is no longer accepted by PCI DSS and most compliance frameworks.'
            Impact     = 'Opt-in: older clients, SQL Server versions and .NET applications without TLS 1.2 support lose connectivity. Enabled by the WebServer profile.'
            References = @{
                Benchmark   = 'Microsoft guidance: TLS/SSL settings (SCHANNEL protocols)'
                MitreAttack = @('T1557', 'T1040')
            }
        }
        @{
            Id         = 'NET-008'
            Title      = 'TLS 1.1 is disabled for server connections'
            Category   = 'Network'
            Severity   = 'Medium'
            Type       = 'Registry'
            Target     = @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'; Name = 'Enabled'; ValueType = 'DWord' }
            Expected   = 0
            OptIn      = $true
            RebootRequired = $true
            Rationale  = 'TLS 1.1 is deprecated (RFC 8996) and should be replaced by TLS 1.2 or 1.3.'
            Impact     = 'Opt-in: clients limited to TLS 1.1 lose connectivity. Enabled by the WebServer profile.'
            References = @{
                Benchmark   = 'Microsoft guidance: TLS/SSL settings (SCHANNEL protocols)'
                MitreAttack = @('T1557', 'T1040')
            }
        }
    )
}
