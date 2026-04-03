function Invoke-ServicesHardening {
    param($Config, [switch]$ReportOnly)

    $results = @()
    $cfg     = $Config.Services

    foreach ($svcName in $cfg.DisableServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue

        if ($null -eq $svc) {
            # Service doesn't exist on this server — skip silently
            continue
        }

        if ($svc.StartType -eq "Disabled") {
            $results += New-CheckResult "Services" "Service Disabled: $svcName" "PASS" `
                "$($svc.DisplayName) is already disabled." "Medium" "CIS Services"
        } else {
            if (-not $ReportOnly) {
                try {
                    Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
                    Set-Service  -Name $svcName -StartupType Disabled
                    Write-Log "Service disabled: $svcName ($($svc.DisplayName))"
                    $results += New-CheckResult "Services" "Service Disabled: $svcName" "FIXED" `
                        "$($svc.DisplayName) was $($svc.StartType). Now disabled and stopped." "Medium" "CIS Services"
                } catch {
                    $results += New-CheckResult "Services" "Service Disabled: $svcName" "FAIL" `
                        "Failed to disable $($svc.DisplayName): $_" "Medium" "CIS Services"
                }
            } else {
                $results += New-CheckResult "Services" "Service Disabled: $svcName" "FAIL" `
                    "$($svc.DisplayName) is $($svc.StartType) — should be disabled." "Medium" "CIS Services"
            }
        }
    }

    # ── Check: Print Spooler (common attack vector) ───────────────
    $spooler = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
    if ($spooler -and $spooler.StartType -ne "Disabled") {
        $results += New-CheckResult "Services" "Print Spooler Running" "FAIL" `
            "Print Spooler is enabled. Disable on servers that don't need printing (PrintNightmare risk)." "High" "CIS CVE-2021-34527"
    } elseif ($spooler) {
        $results += New-CheckResult "Services" "Print Spooler Disabled" "PASS" `
            "Print Spooler is disabled — PrintNightmare mitigated." "High" "CIS CVE-2021-34527"
    }

    # ── Check: Remote Registry ────────────────────────────────────
    $remReg = Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue
    if ($remReg -and $remReg.StartType -ne "Disabled") {
        if (-not $ReportOnly) {
            Stop-Service "RemoteRegistry" -Force -ErrorAction SilentlyContinue
            Set-Service  "RemoteRegistry" -StartupType Disabled
            Write-Log "Remote Registry disabled."
            $results += New-CheckResult "Services" "Remote Registry Disabled" "FIXED" `
                "Remote Registry was running. Now disabled." "High" "CIS 18.4.1"
        } else {
            $results += New-CheckResult "Services" "Remote Registry Disabled" "FAIL" `
                "Remote Registry is RUNNING — allows remote registry edits." "High" "CIS 18.4.1"
        }
    } else {
        $results += New-CheckResult "Services" "Remote Registry Disabled" "PASS" `
            "Remote Registry is disabled." "High" "CIS 18.4.1"
    }

    return $results
}
