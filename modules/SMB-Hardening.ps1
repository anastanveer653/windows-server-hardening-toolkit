function Invoke-SMBHardening {
    param($Config, [switch]$ReportOnly)

    $results = @()
    $cfg = $Config.SMB

    # ── Check 1: SMBv1 ───────────────────────────────────────────
    $smb1 = Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol
    if ($smb1 -eq $false) {
        $results += New-CheckResult "SMB" "SMBv1 Disabled" "PASS" `
            "SMBv1 is already disabled." "Critical" "CIS 18.3.3"
    } else {
        if (-not $ReportOnly -and $cfg.DisableSMBv1) {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false
            Write-Log "SMBv1 disabled."
            $results += New-CheckResult "SMB" "SMBv1 Disabled" "FIXED" `
                "SMBv1 was enabled. Now disabled." "Critical" "CIS 18.3.3"
        } else {
            $results += New-CheckResult "SMB" "SMBv1 Disabled" "FAIL" `
                "SMBv1 is ENABLED — vulnerable to EternalBlue/WannaCry." "Critical" "CIS 18.3.3"
        }
    }

    # ── Check 2: SMB Signing ─────────────────────────────────────
    $signing = Get-SmbServerConfiguration | Select-Object -ExpandProperty RequireSecuritySignature
    if ($signing -eq $true) {
        $results += New-CheckResult "SMB" "SMB Signing Required" "PASS" `
            "SMB packet signing is enforced." "High" "CIS 2.3.8.3"
    } else {
        if (-not $ReportOnly -and $cfg.EnableSMBSigning) {
            Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -Confirm:$false
            Write-Log "SMB signing enabled."
            $results += New-CheckResult "SMB" "SMB Signing Required" "FIXED" `
                "SMB signing was not required. Now enforced." "High" "CIS 2.3.8.3"
        } else {
            $results += New-CheckResult "SMB" "SMB Signing Required" "FAIL" `
                "SMB signing is NOT required — vulnerable to MITM relay attacks." "High" "CIS 2.3.8.3"
        }
    }

    # ── Check 3: SMB Encryption ──────────────────────────────────
    $enc = Get-SmbServerConfiguration | Select-Object -ExpandProperty EncryptData
    if ($enc -eq $true) {
        $results += New-CheckResult "SMB" "SMB Encryption Enabled" "PASS" `
            "SMB data encryption is active." "High" "CIS 18.3.4"
    } else {
        if (-not $ReportOnly -and $cfg.EnableSMBEncryption) {
            Set-SmbServerConfiguration -EncryptData $true -Force -Confirm:$false
            Write-Log "SMB encryption enabled."
            $results += New-CheckResult "SMB" "SMB Encryption Enabled" "FIXED" `
                "SMB data was unencrypted. Encryption now enabled." "High" "CIS 18.3.4"
        } else {
            $results += New-CheckResult "SMB" "SMB Encryption Enabled" "FAIL" `
                "SMB data is transmitted without encryption." "High" "CIS 18.3.4"
        }
    }

    # ── Check 4: SMB Null Sessions ───────────────────────────────
    $nullSession = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "RestrictNullSessAccess" -ErrorAction SilentlyContinue).RestrictNullSessAccess
    if ($nullSession -eq 1) {
        $results += New-CheckResult "SMB" "Null Session Access Restricted" "PASS" `
            "Null session access is blocked." "High" "CIS 2.3.10.2"
    } else {
        if (-not $ReportOnly) {
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
                -Name "RestrictNullSessAccess" -Value 1 -Type DWord -Force
            Write-Log "Null session access restricted."
            $results += New-CheckResult "SMB" "Null Session Access Restricted" "FIXED" `
                "Null session access was open. Now restricted." "High" "CIS 2.3.10.2"
        } else {
            $results += New-CheckResult "SMB" "Null Session Access Restricted" "FAIL" `
                "Null session access is NOT restricted." "High" "CIS 2.3.10.2"
        }
    }

    return $results
}
