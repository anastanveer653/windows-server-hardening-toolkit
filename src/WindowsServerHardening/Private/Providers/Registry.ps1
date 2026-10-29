function Get-RegistryState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control,

        [hashtable]$Context
    )

    $target = $Control.Target
    $keyExists = Test-Path -LiteralPath $target.Path
    if (-not $keyExists -and (Get-OptionalValue -Table $target -Key 'SkipIfKeyMissing')) {
        return New-ControlState -Applicable $false -Exists $false -Reason "Registry key '$($target.Path)' does not exist on this system."
    }

    $extra = @{ KeyExisted = $keyExists; CreatedKeyRoot = $null; ValueKind = $null }
    if ($keyExists) {
        $key = Get-Item -LiteralPath $target.Path
        if (@($key.GetValueNames()) -contains $target.Name) {
            $value = $key.GetValue($target.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $extra.ValueKind = $key.GetValueKind($target.Name).ToString()
            return New-ControlState -Value $value -Exists $true -Extra $extra
        }
    }
    else {
        $extra.CreatedKeyRoot = Get-RegistryMissingRoot -Path $target.Path
    }

    # AbsentValue is the documented default when the value is not set. Some defaults changed between
    # releases (for example WDigest is off by default only since Windows Server 2012 R2), so a default
    # can be limited to builds from AbsentValueMinimumBuild onwards.
    $defaultApplies = $target.Contains('AbsentValue')
    if ($defaultApplies -and $target.Contains('AbsentValueMinimumBuild') -and $null -ne $Context) {
        $build = Get-HardeningOSBuild -SystemInfo $Context.System
        $defaultApplies = ($build -eq 0 -or $build -ge [int]$target.AbsentValueMinimumBuild)
    }
    if ($defaultApplies) {
        $display = 'Not configured (Windows default: {0})' -f (Format-HardeningValue -Value $target.AbsentValue)
        return New-ControlState -Value $target.AbsentValue -Exists $false -Display $display -Extra $extra
    }
    return New-ControlState -Value $null -Exists $false -Display 'Not configured' -Extra $extra
}

function Set-RegistryState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control
    )

    $target = $Control.Target
    # New-Item -Force on an *existing* registry key recreates it and drops its values, so only create missing keys.
    if (-not (Test-Path -LiteralPath $target.Path)) {
        New-Item -Path $target.Path -Force -ErrorAction Stop | Out-Null
    }
    $value = ConvertTo-RegistryValue -Value $Control.Expected -Kind $target.ValueType
    New-ItemProperty -LiteralPath $target.Path -Name $target.Name -Value $value -PropertyType $target.ValueType -Force -ErrorAction Stop | Out-Null
}

function Restore-RegistryState {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Change
    )

    $target = $Change.Target
    $previous = $Change.Previous
    if ($previous.Exists) {
        if (-not (Test-Path -LiteralPath $target.Path)) {
            New-Item -Path $target.Path -Force -ErrorAction Stop | Out-Null
        }
        $kind = if ($previous.Extra.ValueKind) { $previous.Extra.ValueKind } else { $target.ValueType }
        $value = ConvertTo-RegistryValue -Value $previous.Value -Kind $kind
        New-ItemProperty -LiteralPath $target.Path -Name $target.Name -Value $value -PropertyType $kind -Force -ErrorAction Stop | Out-Null
        return New-RestoreOutcome -Status Restored -Detail ('Restored {0}\{1} = {2}.' -f $target.Path, $target.Name, (Format-HardeningValue -Value $previous.Value))
    }

    if (Test-Path -LiteralPath $target.Path) {
        Remove-ItemProperty -LiteralPath $target.Path -Name $target.Name -ErrorAction SilentlyContinue
    }
    if ($previous.Extra.CreatedKeyRoot) {
        Remove-EmptyRegistryKey -Path $target.Path -StopAt $previous.Extra.CreatedKeyRoot
    }
    return New-RestoreOutcome -Status Restored -Detail ('Removed {0}\{1} (it was not configured before hardening).' -f $target.Path, $target.Name)
}

function ConvertTo-RegistryValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory)]
        [string]$Kind
    )

    switch ($Kind) {
        'DWord'       { return [int]$Value }
        'QWord'       { return [long]$Value }
        'MultiString' { return , [string[]]@($Value) }
        'Binary'      { return , [byte[]]@($Value) }
        default       { return [string]$Value }
    }
}

function Get-RegistryMissingRoot {
    # Returns the top-most ancestor of Path that does not exist yet, i.e. the key that
    # New-Item -Force will create. Rollback removes it again once it is empty.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $current = $Path
    $missing = $null
    while ($current -and -not (Test-Path -LiteralPath $current)) {
        $missing = $current
        $parent = Split-Path -Path $current -Parent
        if (-not $parent -or $parent -eq $current) { break }
        $current = $parent
    }
    return $missing
}

function Remove-EmptyRegistryKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$StopAt
    )

    $current = $Path
    while ($current -and $current.StartsWith($StopAt, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $current)) {
        $key = Get-Item -LiteralPath $current
        if ($key.ValueCount -gt 0 -or $key.SubKeyCount -gt 0) { break }
        Remove-Item -LiteralPath $current -ErrorAction Stop
        if ($current -eq $StopAt) { break }
        $current = Split-Path -Path $current -Parent
    }
}
