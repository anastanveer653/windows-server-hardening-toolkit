function Get-SmbServerState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control
    )

    $configuration = Get-SmbServerConfiguration -ErrorAction Stop
    $property = $Control.Target.Property
    return New-ControlState -Value $configuration.$property
}

function Set-SmbServerState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control
    )

    $parameters = @{ Force = $true; Confirm = $false; ErrorAction = 'Stop' }
    $parameters[$Control.Target.Property] = $Control.Expected
    Set-SmbServerConfiguration @parameters
}

function Restore-SmbServerState {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Change
    )

    $parameters = @{ Force = $true; Confirm = $false; ErrorAction = 'Stop' }
    $parameters[$Change.Target.Property] = $Change.Previous.Value
    Set-SmbServerConfiguration @parameters
    return New-RestoreOutcome -Status Restored -Detail "Restored SMB server setting $($Change.Target.Property) = $($Change.Previous.Value)."
}
