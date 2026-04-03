function Invoke-WindowsUpdateHardening {
    param($Config, [switch]$ReportOnly)

    $results = @()
    $cfg     = $Config.WindowsUpdate
    $wuPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"

    # Ensure path exists
    if (-not (Test-Path $wuPath) -and -not $ReportOnly) {
        New-Item $wuPath -Force | Out-Null
    }

    # ── Check 1: Automatic Updates Enabled ───────────────────────
    $auEnabled = (Get-ItemProperty $wuPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue).NoAutoUpdate
    if ($auEnabled -eq 0 -or $null -eq $auEnabled) {
        $results += New-CheckResult "WindowsUpdate" "Automatic Updates Enabled" "PASS" `
            "Automatic updates are configured." "High" "CIS 18.9.108.1"
    } else {
        if (-not $ReportOnly -and $cfg.EnableAutomaticUpdates) {
            Set-ItemProperty $wuPath -Name "NoAutoUpdate" -Value 0 -Type DWord -Force
            Write-Log "Automatic updates enabled."
            $results += New-CheckResult "WindowsUpdate" "Automatic Updates Enabled" "FIXED" `
                "Automatic updates were disabled. Now enabled." "High" "CIS 18.9.108.1"
        } else {
            $results += New-CheckResult "WindowsUpdate" "Automatic Updates Enabled" "FAIL" `
                "Automatic updates are DISABLED — server may miss critical security patches." "High" "CIS 18.9.108.1"
        }
    }

    # ── Check 2: Auto-install minor updates ──────────────────────
    $autoInstall = (Get-ItemProperty $wuPath -Name "AutoInstallMinorUpdates" -ErrorAction SilentlyContinue).AutoInstallMinorUpdates
    if ($autoInstall -eq 1) {
        $results += New-CheckResult "WindowsUpdate" "Auto-Install Minor Updates" "PASS" `
            "Minor updates install automatically." "Medium" "CIS 18.9.108.2"
    } else {
        if (-not $ReportOnly -and $cfg.AutoInstallMinorUpdates) {
            Set-ItemProperty $wuPath -Name "AutoInstallMinorUpdates" -Value 1 -Type DWord -Force
            Write-Log "Auto-install minor updates enabled."
            $results += New-CheckResult "WindowsUpdate" "Auto-Install Minor Updates" "FIXED" `
                "Minor updates were not auto-installing. Fixed." "Medium" "CIS 18.9.108.2"
        } else {
            $results += New-CheckResult "WindowsUpdate" "Auto-Install Minor Updates" "FAIL" `
                "Minor updates do not auto-install." "Medium" "CIS 18.9.108.2"
        }
    }

    # ── Check 3: Pending updates ─────────────────────────────────
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $pending = $updateSearcher.Search("IsInstalled=0 and Type='Software'")
        $count   = $pending.Updates.Count

        if ($count -eq 0) {
            $results += New-CheckResult "WindowsUpdate" "No Pending Updates" "PASS" `
                "System is fully up to date." "High" "CIS Patch"
        } else {
            $results += New-CheckResult "WindowsUpdate" "No Pending Updates" "FAIL" `
                "$count pending update(s) found. Run Windows Update immediately." "High" "CIS Patch"
        }
    } catch {
        $results += New-CheckResult "WindowsUpdate" "No Pending Updates" "SKIPPED" `
            "Could not query Windows Update service: $_" "High" "CIS Patch"
    }

    return $results
}
