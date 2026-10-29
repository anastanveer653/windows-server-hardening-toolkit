function Test-HardeningNumber {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [object]$Value
    )

    return ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or
        $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [uint64] -or
        $Value -is [single] -or $Value -is [double] -or $Value -is [decimal])
}

function ConvertTo-HardeningBoolean {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($Value -is [bool]) { return $Value }
    if (Test-HardeningNumber -Value $Value) { return ([double]$Value -ne 0) }
    if ($Value -is [string]) {
        if ($Value -match '^(true|1|yes|on)$') { return $true }
        if ($Value -match '^(false|0|no|off)$') { return $false }
    }
    return $null
}

function Compare-HardeningScalar {
    # Returns -1, 0 or 1 like IComparable, or $null when the values cannot be compared.
    # The expected value decides the comparison semantics (boolean, numeric or string).
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Actual,

        [AllowNull()]
        [object]$Expected
    )

    if ($null -eq $Actual -or $null -eq $Expected) {
        if ($null -eq $Actual -and $null -eq $Expected) { return 0 }
        return $null
    }

    if ($Expected -is [bool]) {
        $actualBool = ConvertTo-HardeningBoolean -Value $Actual
        if ($null -eq $actualBool) { return $null }
        if ($actualBool -eq $Expected) { return 0 }
        return 1
    }

    if (Test-HardeningNumber -Value $Expected) {
        $number = 0.0
        if (Test-HardeningNumber -Value $Actual) {
            $number = [double]$Actual
        }
        elseif (-not [double]::TryParse([string]$Actual, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$number)) {
            return $null
        }
        return [Math]::Sign($number.CompareTo([double]$Expected))
    }

    return [Math]::Sign([string]::Compare([string]$Actual, [string]$Expected, [System.StringComparison]::OrdinalIgnoreCase))
}

function Test-HardeningValue {
    # Evaluates an actual value against a control's operator. Dictionaries (for example one value
    # per firewall profile) are compliant only when every entry is compliant.
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()]
        [object]$Actual,

        [Parameter(Mandatory)]
        [pscustomobject]$Control
    )

    if ($Actual -is [System.Collections.IDictionary]) {
        if ($Actual.Count -eq 0) { return $false }
        foreach ($key in $Actual.Keys) {
            if (-not (Test-HardeningValue -Actual $Actual[$key] -Control $Control)) { return $false }
        }
        return $true
    }

    if ($null -eq $Actual) {
        return $false
    }

    switch ($Control.Operator) {
        'Equals' {
            return ((Compare-HardeningScalar -Actual $Actual -Expected $Control.Expected) -eq 0)
        }
        'GreaterOrEqual' {
            $result = Compare-HardeningScalar -Actual $Actual -Expected $Control.Expected
            return ($null -ne $result -and $result -ge 0)
        }
        'LessOrEqual' {
            $result = Compare-HardeningScalar -Actual $Actual -Expected $Control.Expected
            return ($null -ne $result -and $result -le 0)
        }
        'Range' {
            $maximum = if ($null -ne $Control.Maximum) { $Control.Maximum } else { $Control.Expected }
            $low = Compare-HardeningScalar -Actual $Actual -Expected $Control.Minimum
            $high = Compare-HardeningScalar -Actual $Actual -Expected $maximum
            return ($null -ne $low -and $null -ne $high -and $low -ge 0 -and $high -le 0)
        }
        'In' {
            foreach ($allowed in @($Control.Allowed)) {
                if ((Compare-HardeningScalar -Actual $Actual -Expected $allowed) -eq 0) { return $true }
            }
            return $false
        }
        default {
            throw "Unsupported operator '$($Control.Operator)' in control $($Control.Id)."
        }
    }
}
