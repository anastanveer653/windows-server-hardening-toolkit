@{
    Controls = @(
        @{
            Id         = 'FW-001'
            Title      = 'Windows Firewall is enabled on all profiles'
            Category   = 'Firewall'
            Severity   = 'Critical'
            Type       = 'FirewallProfile'
            Target     = @{ Property = 'Enabled'; Profiles = @('Domain', 'Private', 'Public') }
            Expected   = 'True'
            Rationale  = 'The host firewall is the last line of defence against lateral movement and exposure of management services.'
            References = @{
                Benchmark   = 'CIS: Windows Firewall: <Domain|Private|Public>: Firewall state = On'
                MitreAttack = @('T1562.004', 'T1021')
            }
        }
        @{
            Id         = 'FW-002'
            Title      = 'Inbound connections are blocked by default on all profiles'
            Category   = 'Firewall'
            Severity   = 'High'
            Type       = 'FirewallProfile'
            Target     = @{ Property = 'DefaultInboundAction'; Profiles = @('Domain', 'Private', 'Public') }
            Expected   = 'Block'
            Rationale  = 'A default-deny inbound posture ensures only explicitly allowed services are reachable.'
            Impact     = 'Services without an allow rule become unreachable. Built-in Windows roles create their own rules.'
            References = @{
                Benchmark   = 'CIS: Windows Firewall: <Domain|Private|Public>: Inbound connections = Block (default)'
                MitreAttack = @('T1562.004', 'T1021')
            }
        }
        @{
            Id         = 'FW-003'
            Title      = 'Firewall logs dropped packets on all profiles'
            Category   = 'Firewall'
            Severity   = 'Low'
            Type       = 'FirewallProfile'
            Target     = @{ Property = 'LogBlocked'; Profiles = @('Domain', 'Private', 'Public') }
            Expected   = 'True'
            Rationale  = 'Dropped packet logs reveal scanning and blocked lateral movement attempts.'
            References = @{
                Benchmark   = 'CIS: Windows Firewall: <Domain|Private|Public>: Logging: Log dropped packets = Yes'
                MitreAttack = @('T1046')
            }
        }
        @{
            Id         = 'FW-004'
            Title      = 'Firewall log size is at least 16 MB on all profiles'
            Category   = 'Firewall'
            Severity   = 'Low'
            Type       = 'FirewallProfile'
            Target     = @{ Property = 'LogMaxSizeKilobytes'; Profiles = @('Domain', 'Private', 'Public') }
            Expected   = 16384
            Operator   = 'GreaterOrEqual'
            Parameter  = 'FirewallLogMaxSizeKB'
            Rationale  = 'The default 4 MB firewall log overwrites itself within minutes on a busy server.'
            References = @{
                Benchmark   = 'CIS: Windows Firewall: <Domain|Private|Public>: Logging: Size limit (KB) = 16,384 KB or greater'
                MitreAttack = @('T1046')
            }
        }
        @{
            Id         = 'FW-005'
            Title      = 'Inbound Telnet (TCP 23) is explicitly blocked'
            Category   = 'Firewall'
            Severity   = 'Medium'
            Type       = 'FirewallRule'
            Target     = @{ Name = 'WSH-Block-Telnet-In'; DisplayName = 'WSH - Block Telnet inbound (TCP 23)'; Direction = 'Inbound'; Protocol = 'TCP'; LocalPort = '23' }
            Expected   = 'Present'
            Rationale  = 'Telnet transmits credentials in cleartext. An explicit block rule takes precedence over any allow rule added later.'
            References = @{
                Benchmark   = 'Hardening best practice: block cleartext management protocols'
                MitreAttack = @('T1021', 'T1040')
            }
        }
        @{
            Id         = 'FW-006'
            Title      = 'Inbound FTP (TCP 21) is explicitly blocked'
            Category   = 'Firewall'
            Severity   = 'Low'
            Type       = 'FirewallRule'
            Target     = @{ Name = 'WSH-Block-FTP-In'; DisplayName = 'WSH - Block FTP inbound (TCP 21)'; Direction = 'Inbound'; Protocol = 'TCP'; LocalPort = '21' }
            Expected   = 'Present'
            Rationale  = 'FTP transmits credentials and data in cleartext; use SFTP or FTPS instead.'
            Impact     = 'Breaks FTP services hosted on this server. The WebServer profile excludes this control.'
            References = @{
                Benchmark   = 'Hardening best practice: block cleartext file transfer protocols'
                MitreAttack = @('T1040', 'T1105')
            }
        }
        @{
            Id         = 'FW-007'
            Title      = 'Remote Desktop is not reachable from any address'
            Category   = 'Firewall'
            Severity   = 'High'
            Type       = 'Custom'
            Target     = @{ Check = 'RdpFirewallScope'; ManualRemediation = 'Restrict the remote address scope of the Remote Desktop allow rules to management subnets or jump hosts, or publish RDP through a gateway.' }
            Expected   = 0
            Rationale  = 'RDP exposed to every address is a leading initial access vector for ransomware operators.'
            References = @{
                Benchmark   = 'Hardening best practice: restrict management protocols to administrative networks'
                MitreAttack = @('T1021.001', 'T1133', 'T1110')
            }
        }
    )
}
