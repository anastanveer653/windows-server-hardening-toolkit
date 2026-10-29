# Advanced audit policy is read with "auditpol /backup", whose CSV carries the subcategory GUID and a
# numeric setting (0 none, 1 success, 2 failure, 3 both). Unlike "auditpol /get" text output this does
# not depend on the display language of the operating system.

$script:AuditFlags = @{ None = 0; Success = 1; Failure = 2; SuccessAndFailure = 3 }

function ConvertTo-AuditPolicyFlag {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [string]$Setting
    )

    if (-not $script:AuditFlags.Contains($Setting)) {
        throw "Invalid audit setting '$Setting'. Valid values: $($script:AuditFlags.Keys -join ', ')."
    }
    return $script:AuditFlags[$Setting]
}

function Format-AuditPolicyFlag {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [int]$Flag
    )

    switch ($Flag) {
        0       { return 'No Auditing' }
        1       { return 'Success' }
        2       { return 'Failure' }
        3       { return 'Success and Failure' }
        default { return "Unknown ($Flag)" }
    }
}

function ConvertFrom-AuditPolicyBackup {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$Content
    )

    $settings = @{}
    $lines = @($Content | Select-Object -Skip 1 | Where-Object { $_ -and $_.Trim() })
    if ($lines.Count -eq 0) {
        return $settings
    }

    $header = 'Machine', 'Target', 'Subcategory', 'Guid', 'Inclusion', 'Exclusion', 'Value'
    foreach ($row in @($lines | ConvertFrom-Csv -Header $header)) {
        $guid = [string]$row.Guid
        if ($guid -match '^\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$') {
            $flag = 0
            [void][int]::TryParse([string]$row.Value, [ref]$flag)
            $settings[$guid.ToUpperInvariant()] = $flag
        }
    }
    return $settings
}

function Get-AuditPolicySnapshot {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $file = New-HardeningTempPath -Extension '.csv'
    try {
        $result = Invoke-HardeningNativeCommand -FilePath 'auditpol.exe' -ArgumentList @('/backup', "/file:$file")
        if ($result.ExitCode -ne 0 -or -not [System.IO.File]::Exists($file)) {
            throw "auditpol /backup failed (exit code $($result.ExitCode)). Reading audit policy requires administrator rights. $($result.Output)".Trim()
        }
        return ConvertFrom-AuditPolicyBackup -Content ([System.IO.File]::ReadAllLines($file))
    }
    finally {
        Remove-HardeningTempPath -Path $file
    }
}

function Get-AuditPolicyState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control,

        [Parameter(Mandatory)]
        [hashtable]$Context
    )

    if (-not $Context.Cache.Contains('AuditPolicy')) {
        try {
            $Context.Cache['AuditPolicy'] = Get-AuditPolicySnapshot
        }
        catch {
            # Remember the failure so the remaining audit controls do not run auditpol again.
            $Context.Cache['AuditPolicy'] = $_.Exception.Message
        }
    }

    $guid = ([string]$Control.Target.SubcategoryGuid).ToUpperInvariant()
    $snapshot = $Context.Cache['AuditPolicy']
    if ($snapshot -is [string]) {
        throw $snapshot
    }
    if (-not $snapshot.Contains($guid)) {
        return New-ControlState -Applicable $false -Exists $false -Reason "Audit subcategory '$($Control.Target.Subcategory)' $guid is not available on this system."
    }

    $flag = [int]$snapshot[$guid]
    return New-ControlState -Value $flag -Display (Format-AuditPolicyFlag -Flag $flag)
}

function Test-AuditPolicyState {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control,

        [Parameter(Mandatory)]
        [pscustomobject]$State
    )

    $required = ConvertTo-AuditPolicyFlag -Setting $Control.Expected
    return ((([int]$State.Value) -band $required) -eq $required)
}

function Set-AuditPolicyState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control,

        [Parameter(Mandatory)]
        [hashtable]$Context,

        [Parameter(Mandatory)]
        [pscustomobject]$State
    )

    # Only add the missing bits; never turn off auditing that is already more verbose than required.
    $desired = ([int]$State.Value) -bor (ConvertTo-AuditPolicyFlag -Setting $Control.Expected)
    Set-AuditPolicyFlag -Guid $Control.Target.SubcategoryGuid -Flag $desired
    $Context.Cache.Remove('AuditPolicy')
}

function Restore-AuditPolicyState {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Change
    )

    $flag = [int]$Change.Previous.Value
    Set-AuditPolicyFlag -Guid $Change.Target.SubcategoryGuid -Flag $flag
    return New-RestoreOutcome -Status Restored -Detail "Restored audit subcategory '$($Change.Target.Subcategory)' to $(Format-AuditPolicyFlag -Flag $flag)."
}

function Set-AuditPolicyFlag {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Guid,

        [Parameter(Mandatory)]
        [int]$Flag
    )

    $success = if ($Flag -band 1) { 'enable' } else { 'disable' }
    $failure = if ($Flag -band 2) { 'enable' } else { 'disable' }
    $result = Invoke-HardeningNativeCommand -FilePath 'auditpol.exe' -ArgumentList @('/set', "/subcategory:$Guid", "/success:$success", "/failure:$failure")
    if ($result.ExitCode -ne 0) {
        throw "auditpol /set failed for subcategory $Guid (exit code $($result.ExitCode)): $($result.Output) $($result.Error)".Trim()
    }
}
