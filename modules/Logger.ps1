function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $entry -ErrorAction SilentlyContinue

    switch ($Level) {
        "WARN"  { Write-Host "    ⚠  $Message" -ForegroundColor Yellow }
        "ERROR" { Write-Host "    ✖  $Message" -ForegroundColor Red }
        default { Write-Verbose $Message }
    }
}

function New-CheckResult {
    param(
        [string]$Category,
        [string]$Check,
        [string]$Status,       # PASS / FAIL / FIXED / SKIPPED
        [string]$Details = "",
        [string]$Severity = "Medium",  # Low / Medium / High / Critical
        [string]$CISControl = ""
    )
    return [PSCustomObject]@{
        Category   = $Category
        Check      = $Check
        Status     = $Status
        Details    = $Details
        Severity   = $Severity
        CISControl = $CISControl
        Timestamp  = (Get-Date -Format "HH:mm:ss")
    }
}
