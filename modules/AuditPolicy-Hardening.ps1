function Invoke-AuditPolicyHardening {
    param($Config, [switch]$ReportOnly)

    $results = @()
    $cfg     = $Config.AuditPolicy
    $evtCfg  = $Config.EventLog

    # Helper — check and set audit category
    function Set-AuditCategory {
        param([string]$Category, [string]$SubCategory, [string]$CISRef, [bool]$Enable)

        $current = auditpol /get /subcategory:"$SubCategory" 2>$null
        $enabled = $current -match "Success and Failure|Success|Failure"

        if ($enabled) {
            return New-CheckResult "AuditPolicy" "Audit: $SubCategory" "PASS" `
                "Auditing is configured." "Medium" $CISRef
        } else {
            if (-not $ReportOnly -and $Enable) {
                auditpol /set /subcategory:"$SubCategory" /success:enable /failure:enable | Out-Null
                Write-Log "Audit policy set: $SubCategory"
                return New-CheckResult "AuditPolicy" "Audit: $SubCategory" "FIXED" `
                    "Audit was off. Now enabled for Success and Failure." "Medium" $CISRef
            } else {
                return New-CheckResult "AuditPolicy" "Audit: $SubCategory" "FAIL" `
                    "Auditing is NOT configured for $SubCategory." "Medium" $CISRef
            }
        }
    }

    # ── Audit Subcategories ───────────────────────────────────────
    $results += Set-AuditCategory "Logon" "Logon"                   "CIS 17.5.1"  $cfg.AuditLogonEvents
    $results += Set-AuditCategory "Logon" "Logoff"                  "CIS 17.5.2"  $cfg.AuditLogonEvents
    $results += Set-AuditCategory "Logon" "Account Lockout"         "CIS 17.5.3"  $cfg.AuditLogonEvents
    $results += Set-AuditCategory "Logon" "Credential Validation"   "CIS 17.1.1"  $cfg.AuditAccountLogon
    $results += Set-AuditCategory "Account" "User Account Management" "CIS 17.2.1" $cfg.AuditAccountManagement
    $results += Set-AuditCategory "Account" "Security Group Management" "CIS 17.2.5" $cfg.AuditAccountManagement
    $results += Set-AuditCategory "Policy" "Audit Policy Change"    "CIS 17.7.1"  $cfg.AuditPolicyChange
    $results += Set-AuditCategory "Policy" "Authentication Policy Change" "CIS 17.7.2" $cfg.AuditPolicyChange
    $results += Set-AuditCategory "Privilege" "Sensitive Privilege Use" "CIS 17.6.1" $cfg.AuditPrivilegeUse
    $results += Set-AuditCategory "System" "Security System Extension" "CIS 17.9.1" $cfg.AuditSystemEvents
    $results += Set-AuditCategory "System" "System Integrity"       "CIS 17.9.5"  $cfg.AuditSystemEvents

    # ── Event Log Sizes ───────────────────────────────────────────
    function Set-EventLogSize {
        param([string]$LogName, [int]$SizeMB, [string]$CISRef)
        $bytes = $SizeMB * 1MB
        try {
            $log = Get-WinEvent -ListLog $LogName -ErrorAction Stop
            if ($log.MaximumSizeInBytes -ge $bytes) {
                return New-CheckResult "AuditPolicy" "$LogName Log Size" "PASS" `
                    "Log size is $([math]::Round($log.MaximumSizeInBytes/1MB))MB (minimum: ${SizeMB}MB)." "Low" $CISRef
            } else {
                if (-not $ReportOnly) {
                    Limit-EventLog -LogName $LogName -MaximumSize ($bytes) -ErrorAction SilentlyContinue
                    Write-Log "Event log size set: $LogName = ${SizeMB}MB"
                    return New-CheckResult "AuditPolicy" "$LogName Log Size" "FIXED" `
                        "Was $([math]::Round($log.MaximumSizeInBytes/1MB))MB. Set to ${SizeMB}MB." "Low" $CISRef
                } else {
                    return New-CheckResult "AuditPolicy" "$LogName Log Size" "FAIL" `
                        "Log size is $([math]::Round($log.MaximumSizeInBytes/1MB))MB. Recommended: ${SizeMB}MB." "Low" $CISRef
                }
            }
        } catch {
            return New-CheckResult "AuditPolicy" "$LogName Log Size" "SKIPPED" `
                "Could not access log: $_" "Low" $CISRef
        }
    }

    $results += Set-EventLogSize "Security"    $evtCfg.SecurityLogMaxSizeMB    "CIS 18.9.27.1"
    $results += Set-EventLogSize "System"      $evtCfg.SystemLogMaxSizeMB      "CIS 18.9.27.2"
    $results += Set-EventLogSize "Application" $evtCfg.ApplicationLogMaxSizeMB "CIS 18.9.27.3"

    return $results
}
