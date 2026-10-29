function Get-FirewallProfileState {
    # Reads the effective (ActiveStore) value per profile, so settings enforced by Group Policy are reported correctly.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control
    )

    $property = $Control.Target.Property
    $names = if ($Control.Target.Contains('Profiles')) { @($Control.Target.Profiles) } else { @('Domain', 'Private', 'Public') }
    $values = [ordered]@{}
    foreach ($firewallProfile in @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)) {
        if ($names -contains [string]$firewallProfile.Name) {
            $values[[string]$firewallProfile.Name] = [string]$firewallProfile.$property
        }
    }
    return New-ControlState -Value $values
}

function Set-FirewallProfileState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control,

        [Parameter(Mandatory)]
        [pscustomobject]$State
    )

    foreach ($name in @($State.Value.Keys)) {
        if (-not (Test-HardeningValue -Actual $State.Value[$name] -Control $Control)) {
            $parameters = @{ Name = $name; ErrorAction = 'Stop' }
            $parameters[$Control.Target.Property] = $Control.Expected
            Set-NetFirewallProfile @parameters
        }
    }
}

function Restore-FirewallProfileState {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Change
    )

    $property = $Change.Target.Property
    foreach ($name in @($Change.Previous.Value.Keys)) {
        $parameters = @{ Name = $name; ErrorAction = 'Stop' }
        $parameters[$property] = $Change.Previous.Value[$name]
        Set-NetFirewallProfile @parameters
    }
    return New-RestoreOutcome -Status Restored -Detail "Restored firewall profile setting $property ($(Format-HardeningValue -Value $Change.Previous.Value))."
}

function Get-FirewallRuleState {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control
    )

    $rule = Get-NetFirewallRule -Name $Control.Target.Name -ErrorAction SilentlyContinue
    if (-not $rule) {
        return New-ControlState -Value 'Absent' -Exists $false -Display 'Rule not present'
    }

    $enabled = [string]$rule.Enabled
    $action = [string]$rule.Action
    $value = if ($enabled -eq 'True' -and $action -eq 'Block') { 'Present' } else { 'Inactive' }
    $display = 'Rule present (Enabled={0}, Action={1})' -f $enabled, $action
    return New-ControlState -Value $value -Display $display -Extra @{ Enabled = $enabled; Action = $action }
}

function Set-FirewallRuleState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control,

        [Parameter(Mandatory)]
        [pscustomobject]$State
    )

    $target = $Control.Target
    if ($State.Exists) {
        Set-NetFirewallRule -Name $target.Name -Enabled True -Action Block -ErrorAction Stop
        return
    }

    $parameters = @{
        Name        = $target.Name
        DisplayName = $target.DisplayName
        Description = "Created by Windows Server Hardening Toolkit (control $($Control.Id))."
        Group       = 'Windows Server Hardening Toolkit'
        Direction   = $target.Direction
        Protocol    = $target.Protocol
        LocalPort   = $target.LocalPort
        Action      = 'Block'
        Profile     = 'Any'
        Enabled     = 'True'
        ErrorAction = 'Stop'
    }
    New-NetFirewallRule @parameters | Out-Null
}

function Restore-FirewallRuleState {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Change
    )

    $name = $Change.Target.Name
    if (-not $Change.Previous.Exists) {
        Remove-NetFirewallRule -Name $name -ErrorAction Stop
        return New-RestoreOutcome -Status Restored -Detail "Removed firewall rule '$name' created during hardening."
    }

    Set-NetFirewallRule -Name $name -Enabled $Change.Previous.Extra.Enabled -Action $Change.Previous.Extra.Action -ErrorAction Stop
    return New-RestoreOutcome -Status Restored -Detail "Restored firewall rule '$name' (Enabled=$($Change.Previous.Extra.Enabled), Action=$($Change.Previous.Extra.Action))."
}
