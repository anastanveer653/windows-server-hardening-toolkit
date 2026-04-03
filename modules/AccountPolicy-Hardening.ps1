function Invoke-AccountPolicyHardening {
    param($Config, [switch]$ReportOnly)

    $results = @()
    $pwdCfg  = $Config.PasswordPolicy
    $lkCfg   = $Config.AccountLockout

    # Get current policy via net accounts
    $netAccounts = net accounts 2>$null

    function Get-NetAccountsValue {
        param([string]$Pattern)
        $line = $netAccounts | Where-Object { $_ -match $Pattern }
        if ($line -match ":\s+(\S+)") { return $Matches[1] }
        return $null
    }

    # ── Check 1: Minimum Password Length ─────────────────────────
    $minLen = Get-NetAccountsValue "Minimum password length"
    if ([int]$minLen -ge $pwdCfg.MinimumPasswordLength) {
        $results += New-CheckResult "AccountPolicy" "Minimum Password Length" "PASS" `
            "Password length is $minLen (required: $($pwdCfg.MinimumPasswordLength))." "High" "CIS 1.1.4"
    } else {
        if (-not $ReportOnly) {
            net accounts /minpwlen:$($pwdCfg.MinimumPasswordLength) | Out-Null
            Write-Log "Minimum password length set to $($pwdCfg.MinimumPasswordLength)."
            $results += New-CheckResult "AccountPolicy" "Minimum Password Length" "FIXED" `
                "Was $minLen. Set to $($pwdCfg.MinimumPasswordLength)." "High" "CIS 1.1.4"
        } else {
            $results += New-CheckResult "AccountPolicy" "Minimum Password Length" "FAIL" `
                "Password length is $minLen — less than required $($pwdCfg.MinimumPasswordLength)." "High" "CIS 1.1.4"
        }
    }

    # ── Check 2: Maximum Password Age ────────────────────────────
    $maxAge = Get-NetAccountsValue "Maximum password age"
    if ($maxAge -ne "Never" -and [int]$maxAge -le $pwdCfg.MaximumPasswordAge) {
        $results += New-CheckResult "AccountPolicy" "Maximum Password Age" "PASS" `
            "Max password age is $maxAge days (max: $($pwdCfg.MaximumPasswordAge))." "Medium" "CIS 1.1.2"
    } else {
        if (-not $ReportOnly) {
            net accounts /maxpwage:$($pwdCfg.MaximumPasswordAge) | Out-Null
            Write-Log "Maximum password age set to $($pwdCfg.MaximumPasswordAge) days."
            $results += New-CheckResult "AccountPolicy" "Maximum Password Age" "FIXED" `
                "Was $maxAge. Set to $($pwdCfg.MaximumPasswordAge) days." "Medium" "CIS 1.1.2"
        } else {
            $results += New-CheckResult "AccountPolicy" "Maximum Password Age" "FAIL" `
                "Max password age is $maxAge days — should be ≤ $($pwdCfg.MaximumPasswordAge)." "Medium" "CIS 1.1.2"
        }
    }

    # ── Check 3: Password History ─────────────────────────────────
    $history = Get-NetAccountsValue "Length of password history"
    if ([int]$history -ge $pwdCfg.PasswordHistoryCount) {
        $results += New-CheckResult "AccountPolicy" "Password History" "PASS" `
            "Password history remembers $history passwords." "Medium" "CIS 1.1.1"
    } else {
        if (-not $ReportOnly) {
            net accounts /uniquepw:$($pwdCfg.PasswordHistoryCount) | Out-Null
            Write-Log "Password history set to $($pwdCfg.PasswordHistoryCount)."
            $results += New-CheckResult "AccountPolicy" "Password History" "FIXED" `
                "Was $history. Set to $($pwdCfg.PasswordHistoryCount) passwords remembered." "Medium" "CIS 1.1.1"
        } else {
            $results += New-CheckResult "AccountPolicy" "Password History" "FAIL" `
                "History is $history — should be ≥ $($pwdCfg.PasswordHistoryCount)." "Medium" "CIS 1.1.1"
        }
    }

    # ── Check 4: Account Lockout Threshold ───────────────────────
    $lockout = Get-NetAccountsValue "Lockout threshold"
    $lockoutOk = ($lockout -ne "Never" -and [int]$lockout -le $lkCfg.LockoutThreshold -and [int]$lockout -gt 0)
    if ($lockoutOk) {
        $results += New-CheckResult "AccountPolicy" "Account Lockout Threshold" "PASS" `
            "Lockout after $lockout attempts." "High" "CIS 1.2.1"
    } else {
        if (-not $ReportOnly) {
            net accounts /lockoutthreshold:$($lkCfg.LockoutThreshold) | Out-Null
            Write-Log "Lockout threshold set to $($lkCfg.LockoutThreshold)."
            $results += New-CheckResult "AccountPolicy" "Account Lockout Threshold" "FIXED" `
                "Was $lockout. Set to $($lkCfg.LockoutThreshold) attempts." "High" "CIS 1.2.1"
        } else {
            $results += New-CheckResult "AccountPolicy" "Account Lockout Threshold" "FAIL" `
                "Lockout is $lockout — should be ≤ $($lkCfg.LockoutThreshold)." "High" "CIS 1.2.1"
        }
    }

    # ── Check 5: Guest Account Disabled ──────────────────────────
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guest -and $guest.Enabled -eq $false) {
        $results += New-CheckResult "AccountPolicy" "Guest Account Disabled" "PASS" `
            "Built-in Guest account is disabled." "High" "CIS 2.3.1.2"
    } elseif ($guest) {
        if (-not $ReportOnly) {
            Disable-LocalUser -Name "Guest"
            Write-Log "Guest account disabled."
            $results += New-CheckResult "AccountPolicy" "Guest Account Disabled" "FIXED" `
                "Guest account was enabled. Now disabled." "High" "CIS 2.3.1.2"
        } else {
            $results += New-CheckResult "AccountPolicy" "Guest Account Disabled" "FAIL" `
                "Built-in Guest account is ENABLED." "High" "CIS 2.3.1.2"
        }
    }

    return $results
}
