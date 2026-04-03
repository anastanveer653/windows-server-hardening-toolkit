function Invoke-NTLMHardening {
    param($Config, [switch]$ReportOnly)

    $results = @()
    $cfg     = $Config.NTLM
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

    # ── Check 1: LmCompatibilityLevel (NTLMv2 only) ──────────────
    # Level 5 = Send NTLMv2 only, refuse LM and NTLM
    $current = (Get-ItemProperty $lsaPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
    if ($current -eq 5) {
        $results += New-CheckResult "NTLM" "NTLMv2 Only (Level 5)" "PASS" `
            "LmCompatibilityLevel is 5 — NTLMv2 enforced." "Critical" "CIS 2.3.11.7"
    } else {
        if (-not $ReportOnly -and $cfg.RestrictNTLM) {
            Set-ItemProperty $lsaPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force
            Write-Log "LmCompatibilityLevel set to 5 (NTLMv2 only)."
            $results += New-CheckResult "NTLM" "NTLMv2 Only (Level 5)" "FIXED" `
                "Was level $current. Set to 5 — only NTLMv2 accepted now." "Critical" "CIS 2.3.11.7"
        } else {
            $results += New-CheckResult "NTLM" "NTLMv2 Only (Level 5)" "FAIL" `
                "LmCompatibilityLevel is $current — weak NTLM/LM authentication accepted." "Critical" "CIS 2.3.11.7"
        }
    }

    # ── Check 2: Disable LM Hash Storage ─────────────────────────
    $noLMHash = (Get-ItemProperty $lsaPath -Name "NoLMHash" -ErrorAction SilentlyContinue).NoLMHash
    if ($noLMHash -eq 1) {
        $results += New-CheckResult "NTLM" "LM Hash Storage Disabled" "PASS" `
            "LM hashes are not stored." "Critical" "CIS 2.3.11.4"
    } else {
        if (-not $ReportOnly -and $cfg.DisableLMHash) {
            Set-ItemProperty $lsaPath -Name "NoLMHash" -Value 1 -Type DWord -Force
            Write-Log "LM hash storage disabled."
            $results += New-CheckResult "NTLM" "LM Hash Storage Disabled" "FIXED" `
                "LM hashes were being stored. Disabled now." "Critical" "CIS 2.3.11.4"
        } else {
            $results += New-CheckResult "NTLM" "LM Hash Storage Disabled" "FAIL" `
                "LM hashes are being stored — crackable with rainbow tables." "Critical" "CIS 2.3.11.4"
        }
    }

    # ── Check 3: Disable WDigest (credential caching) ────────────
    $wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    $wdigest = (Get-ItemProperty $wdigestPath -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential
    if ($wdigest -eq 0) {
        $results += New-CheckResult "NTLM" "WDigest Authentication Disabled" "PASS" `
            "WDigest is off — plaintext passwords not cached in LSASS." "Critical" "CIS 18.3.7"
    } else {
        if (-not $ReportOnly) {
            if (-not (Test-Path $wdigestPath)) { New-Item $wdigestPath -Force | Out-Null }
            Set-ItemProperty $wdigestPath -Name "UseLogonCredential" -Value 0 -Type DWord -Force
            Write-Log "WDigest authentication disabled."
            $results += New-CheckResult "NTLM" "WDigest Authentication Disabled" "FIXED" `
                "WDigest was enabled — plaintext passwords cached. Now disabled." "Critical" "CIS 18.3.7"
        } else {
            $results += New-CheckResult "NTLM" "WDigest Authentication Disabled" "FAIL" `
                "WDigest is ENABLED — Mimikatz can dump plaintext passwords from LSASS." "Critical" "CIS 18.3.7"
        }
    }

    # ── Check 4: LSA Protection ───────────────────────────────────
    $lsaProtect = (Get-ItemProperty $lsaPath -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL
    if ($lsaProtect -eq 1) {
        $results += New-CheckResult "NTLM" "LSA Protected Process" "PASS" `
            "LSASS runs as a protected process — credential theft harder." "High" "CIS 18.3.1"
    } else {
        if (-not $ReportOnly) {
            Set-ItemProperty $lsaPath -Name "RunAsPPL" -Value 1 -Type DWord -Force
            Write-Log "LSA protected process enabled."
            $results += New-CheckResult "NTLM" "LSA Protected Process" "FIXED" `
                "LSASS was unprotected. PPL enabled (reboot required)." "High" "CIS 18.3.1"
        } else {
            $results += New-CheckResult "NTLM" "LSA Protected Process" "FAIL" `
                "LSASS is NOT protected — vulnerable to credential dumping." "High" "CIS 18.3.1"
        }
    }

    return $results
}
