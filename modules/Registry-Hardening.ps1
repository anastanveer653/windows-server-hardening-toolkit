function Invoke-RegistryHardening {
    param($Config, [switch]$ReportOnly)

    $results = @()
    $cfg     = $Config.Registry

    function Set-RegistryCheck {
        param(
            [string]$Name,
            [string]$Path,
            [string]$Key,
            [object]$ExpectedValue,
            [string]$Type = "DWord",
            [string]$Severity = "Medium",
            [string]$CISRef = "",
            [string]$FailMessage = ""
        )
        try {
            if (-not (Test-Path $Path)) {
                if (-not $ReportOnly) { New-Item $Path -Force | Out-Null }
                else {
                    return New-CheckResult "Registry" $Name "FAIL" "Registry path does not exist: $Path" $Severity $CISRef
                }
            }
            $current = (Get-ItemProperty $Path -Name $Key -ErrorAction SilentlyContinue).$Key

            if ($current -eq $ExpectedValue) {
                return New-CheckResult "Registry" $Name "PASS" "Value is correct ($Key = $ExpectedValue)." $Severity $CISRef
            } else {
                if (-not $ReportOnly) {
                    Set-ItemProperty $Path -Name $Key -Value $ExpectedValue -Type $Type -Force
                    Write-Log "Registry set: $Path\$Key = $ExpectedValue"
                    return New-CheckResult "Registry" $Name "FIXED" `
                        "Was '$current'. Set to '$ExpectedValue'." $Severity $CISRef
                } else {
                    $msg = if ($FailMessage) { $FailMessage } else { "Value is '$current', expected '$ExpectedValue'." }
                    return New-CheckResult "Registry" $Name "FAIL" $msg $Severity $CISRef
                }
            }
        } catch {
            return New-CheckResult "Registry" $Name "FAIL" "Error: $_" $Severity $CISRef
        }
    }

    # ── Autorun / Autoplay disabled ───────────────────────────────
    $results += Set-RegistryCheck "Autorun Disabled" `
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        "NoDriveTypeAutoRun" 255 "DWord" "High" "CIS 18.8.45.1" `
        "Autorun is NOT disabled — malware can execute automatically from USB."

    # ── Hide last logged-on username ──────────────────────────────
    $results += Set-RegistryCheck "Hide Last Logged-On User" `
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        "DontDisplayLastUserName" 1 "DWord" "Medium" "CIS 2.3.7.1" `
        "Last username is displayed on login screen — information disclosure risk."

    # ── Disable anonymous enumeration of SAM accounts ─────────────
    $results += Set-RegistryCheck "No Anonymous SAM Enumeration" `
        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "RestrictAnonymousSAM" 1 "DWord" "High" "CIS 2.3.10.1" `
        "Anonymous enumeration of SAM accounts is allowed."

    # ── Disable anonymous enumeration of shares ───────────────────
    $results += Set-RegistryCheck "No Anonymous Share Enumeration" `
        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        "RestrictAnonymous" 1 "DWord" "High" "CIS 2.3.10.2" `
        "Anonymous share enumeration is allowed."

    # ── Enable DEP (Data Execution Prevention) ────────────────────
    $results += Set-RegistryCheck "Data Execution Prevention (DEP)" `
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
        "EnableExecuteProtection" 1 "DWord" "High" "CIS 18.8.21.3" `
        "DEP is not enforced via registry."

    # ── Legal notice caption ──────────────────────────────────────
    if ($cfg.LegalNotice) {
        $results += Set-RegistryCheck "Legal Notice Text" `
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            "LegalNoticeText" $cfg.LegalNoticeText "String" "Low" "CIS 2.3.7.4" `
            "No legal notice is configured on the login screen."

        $results += Set-RegistryCheck "Legal Notice Caption" `
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
            "LegalNoticeCaption" "WARNING" "String" "Low" "CIS 2.3.7.5" `
            "No legal notice caption is configured."
    }

    # ── Disable storing credentials in plain text (CredSSP) ───────
    $results += Set-RegistryCheck "CredSSP: No Plain-Text Creds" `
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" `
        "AllowDefCredentialsWhenNTLMOnly" 0 "DWord" "High" "CIS 18.9.11.1" `
        "CredSSP may store credentials in plaintext during delegation."

    # ── Disable Windows Script Host (prevents malicious VBS/JS) ───
    $results += Set-RegistryCheck "Windows Script Host Disabled" `
        "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" `
        "Enabled" 0 "DWord" "Medium" "CIS Custom" `
        "Windows Script Host is enabled — allows VBScript/JScript malware execution."

    # ── Disable RDP clipboard sharing ─────────────────────────────
    if (-not $cfg.DisableRemoteDesktopClipboard) {
        # Only check; don't disable if config says keep it
        $rdpClip = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
            -Name "fDisableClip" -ErrorAction SilentlyContinue).fDisableClip
        if ($rdpClip -eq 1) {
            $results += New-CheckResult "Registry" "RDP Clipboard Sharing" "PASS" `
                "RDP clipboard redirection is disabled." "Low" "CIS 18.9.58.3.3"
        } else {
            $results += New-CheckResult "Registry" "RDP Clipboard Sharing" "FAIL" `
                "RDP clipboard sharing is enabled — data exfiltration risk." "Low" "CIS 18.9.58.3.3"
        }
    }

    return $results
}
