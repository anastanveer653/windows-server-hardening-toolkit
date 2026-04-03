function Invoke-FirewallHardening {
    param($Config, [switch]$ReportOnly)

    $results = @()
    $cfg     = $Config.Firewall

    # ── Check 1: Firewall Enabled on all profiles ─────────────────
    $profiles = Get-NetFirewallProfile -All
    $allEnabled = ($profiles | Where-Object { $_.Enabled -eq $false }).Count -eq 0

    if ($allEnabled) {
        $results += New-CheckResult "Firewall" "Firewall Enabled (All Profiles)" "PASS" `
            "Firewall is active on Domain, Private, and Public profiles." "Critical" "CIS 9.1.1"
    } else {
        if (-not $ReportOnly -and $cfg.EnableFirewall) {
            Set-NetFirewallProfile -All -Enabled True
            Write-Log "Windows Firewall enabled on all profiles."
            $results += New-CheckResult "Firewall" "Firewall Enabled (All Profiles)" "FIXED" `
                "Some profiles had firewall off. All profiles now enabled." "Critical" "CIS 9.1.1"
        } else {
            $disabled = ($profiles | Where-Object { $_.Enabled -eq $false }).Name -join ", "
            $results += New-CheckResult "Firewall" "Firewall Enabled (All Profiles)" "FAIL" `
                "Firewall is DISABLED on: $disabled" "Critical" "CIS 9.1.1"
        }
    }

    # ── Check 2: Default inbound action = Block ───────────────────
    $inboundBlock = ($profiles | Where-Object { $_.DefaultInboundAction -ne "Block" }).Count -eq 0
    if ($inboundBlock) {
        $results += New-CheckResult "Firewall" "Default Inbound = Block" "PASS" `
            "All profiles block inbound by default." "High" "CIS 9.1.2"
    } else {
        if (-not $ReportOnly -and $cfg.BlockInboundByDefault) {
            Set-NetFirewallProfile -All -DefaultInboundAction Block
            Write-Log "Default inbound action set to Block on all profiles."
            $results += New-CheckResult "Firewall" "Default Inbound = Block" "FIXED" `
                "Some profiles allowed inbound by default. Now set to Block." "High" "CIS 9.1.2"
        } else {
            $results += New-CheckResult "Firewall" "Default Inbound = Block" "FAIL" `
                "One or more profiles allow inbound connections by default." "High" "CIS 9.1.2"
        }
    }

    # ── Check 3: Block Telnet (port 23) ──────────────────────────
    $telnetRule = Get-NetFirewallRule -DisplayName "Block Telnet Inbound" -ErrorAction SilentlyContinue
    if ($telnetRule) {
        $results += New-CheckResult "Firewall" "Telnet Port 23 Blocked" "PASS" `
            "Telnet inbound rule exists." "High" "CIS Custom"
    } else {
        if (-not $ReportOnly -and $cfg.BlockTelnet) {
            New-NetFirewallRule -DisplayName "Block Telnet Inbound" `
                -Direction Inbound -Protocol TCP -LocalPort 23 `
                -Action Block -Profile Any | Out-Null
            Write-Log "Firewall rule added: Block Telnet port 23."
            $results += New-CheckResult "Firewall" "Telnet Port 23 Blocked" "FIXED" `
                "Telnet was not explicitly blocked. Rule added." "High" "CIS Custom"
        } else {
            $results += New-CheckResult "Firewall" "Telnet Port 23 Blocked" "FAIL" `
                "No explicit rule blocking Telnet (port 23)." "High" "CIS Custom"
        }
    }

    # ── Check 4: Block FTP (port 21) ─────────────────────────────
    $ftpRule = Get-NetFirewallRule -DisplayName "Block FTP Inbound" -ErrorAction SilentlyContinue
    if ($ftpRule) {
        $results += New-CheckResult "Firewall" "FTP Port 21 Blocked" "PASS" `
            "FTP inbound block rule exists." "Medium" "CIS Custom"
    } else {
        if (-not $ReportOnly -and $cfg.BlockFTP) {
            New-NetFirewallRule -DisplayName "Block FTP Inbound" `
                -Direction Inbound -Protocol TCP -LocalPort 21 `
                -Action Block -Profile Any | Out-Null
            Write-Log "Firewall rule added: Block FTP port 21."
            $results += New-CheckResult "Firewall" "FTP Port 21 Blocked" "FIXED" `
                "FTP was not explicitly blocked. Rule added." "Medium" "CIS Custom"
        } else {
            $results += New-CheckResult "Firewall" "FTP Port 21 Blocked" "FAIL" `
                "No explicit rule blocking FTP (port 21)." "Medium" "CIS Custom"
        }
    }

    # ── Check 5: RDP restricted to subnet ────────────────────────
    $rdpRules = Get-NetFirewallRule -DisplayName "Remote Desktop*" -ErrorAction SilentlyContinue |
                Where-Object { $_.Direction -eq "Inbound" -and $_.Enabled -eq $true }
    if ($rdpRules) {
        $results += New-CheckResult "Firewall" "RDP Rule Present" "PASS" `
            "RDP firewall rule is configured. Verify it restricts source IPs." "Medium" "CIS 9.3.6"
    } else {
        $results += New-CheckResult "Firewall" "RDP Rule Present" "FAIL" `
            "No active inbound RDP firewall rule found. Verify RDP access is controlled." "Medium" "CIS 9.3.6"
    }

    return $results
}
