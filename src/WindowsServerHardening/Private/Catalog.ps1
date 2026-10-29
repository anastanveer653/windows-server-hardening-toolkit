$script:ValidSeverities = @('Critical', 'High', 'Medium', 'Low')
$script:ValidOperators  = @('Equals', 'GreaterOrEqual', 'LessOrEqual', 'Range', 'In')
$script:ValidTypes      = @('Registry', 'Service', 'SmbServer', 'FirewallProfile', 'FirewallRule', 'AuditPolicy', 'SecurityPolicy', 'Custom')
$script:ValidRoles      = @('DomainController', 'MemberServer', 'StandaloneServer', 'Workstation')
$script:SeverityWeight  = @{ Critical = 10; High = 5; Medium = 3; Low = 1 }

$script:RequiredTargetKeys = @{
    Registry        = @('Path', 'Name')
    Service         = @('Name')
    SmbServer       = @('Property')
    FirewallProfile = @('Property')
    FirewallRule    = @('Name', 'DisplayName', 'Direction', 'Protocol', 'LocalPort')
    AuditPolicy     = @('SubcategoryGuid', 'Subcategory')
    SecurityPolicy  = @('Key')
    Custom          = @('Check')
}

function Get-HardeningCatalog {
    [CmdletBinding()]
    param(
        [string]$Path = $script:ControlsPath,

        [switch]$Force
    )

    if ($script:Catalog -and -not $Force -and $Path -eq $script:ControlsPath) {
        return $script:Catalog
    }

    $controls = [System.Collections.Generic.List[object]]::new()
    $order = 0
    foreach ($file in @(Get-ChildItem -LiteralPath $Path -Filter '*.psd1' | Sort-Object -Property Name)) {
        $data = Import-PowerShellDataFile -LiteralPath $file.FullName
        if (-not $data.Contains('Controls')) {
            throw "Catalog file '$($file.Name)' does not define a 'Controls' array."
        }
        foreach ($definition in @($data.Controls)) {
            $order++
            $controls.Add((ConvertTo-HardeningControl -Definition $definition -Source $file.Name -Order $order))
        }
    }

    $duplicates = @($controls | Group-Object -Property Id | Where-Object { $_.Count -gt 1 })
    if ($duplicates.Count -gt 0) {
        throw "Duplicate control IDs in catalog: $(($duplicates | ForEach-Object { $_.Name }) -join ', ')"
    }

    $catalog = $controls.ToArray()
    if ($Path -eq $script:ControlsPath) {
        $script:Catalog = $catalog
    }
    return $catalog
}

function ConvertTo-HardeningControl {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Definition,

        [string]$Source = 'inline',

        [int]$Order = 0
    )

    $id = if ($Definition.Contains('Id')) { $Definition.Id } else { '<missing id>' }
    $where = "Control '$id' ($Source)"

    foreach ($key in @('Id', 'Title', 'Category', 'Severity', 'Type', 'Target', 'Rationale')) {
        if (-not $Definition.Contains($key) -or $null -eq $Definition[$key] -or '' -eq $Definition[$key]) {
            throw "$where is missing required field '$key'."
        }
    }
    if ($script:ValidSeverities -notcontains $Definition.Severity) {
        throw "$where has invalid Severity '$($Definition.Severity)'. Valid values: $($script:ValidSeverities -join ', ')."
    }
    if ($script:ValidTypes -notcontains $Definition.Type) {
        throw "$where has invalid Type '$($Definition.Type)'. Valid values: $($script:ValidTypes -join ', ')."
    }
    if ($Definition.Target -isnot [hashtable]) {
        throw "$where must define Target as a hashtable."
    }
    foreach ($key in $script:RequiredTargetKeys[$Definition.Type]) {
        if (-not $Definition.Target.Contains($key)) {
            throw "$where (type $($Definition.Type)) is missing Target.$key."
        }
    }
    if (-not $Definition.Contains('Expected')) {
        throw "$where is missing required field 'Expected'."
    }

    $operator = if ($Definition.Contains('Operator')) { $Definition.Operator } else { 'Equals' }
    if ($script:ValidOperators -notcontains $operator) {
        throw "$where has invalid Operator '$operator'. Valid values: $($script:ValidOperators -join ', ')."
    }
    if ($operator -eq 'Range' -and -not $Definition.Contains('Minimum')) {
        throw "$where uses the Range operator and must define Minimum."
    }
    if ($operator -eq 'In' -and -not $Definition.Contains('Allowed')) {
        throw "$where uses the In operator and must define Allowed."
    }

    $target = $Definition.Target.Clone()
    if ($Definition.Type -eq 'Registry' -and -not $target.Contains('ValueType')) {
        $target.ValueType = 'DWord'
    }

    $minimumBuild = Get-OptionalValue -Table $Definition -Key 'MinimumBuild'
    if ($null -ne $minimumBuild -and $minimumBuild -isnot [int]) {
        throw "$where has a non-numeric MinimumBuild '$minimumBuild'."
    }

    $references = if ($Definition.Contains('References')) { $Definition.References } else { @{} }
    foreach ($role in @(Get-OptionalValue -Table $Definition -Key 'Roles') + @(Get-OptionalValue -Table $Definition -Key 'ExcludeRoles')) {
        if ($role -and $script:ValidRoles -notcontains $role) {
            throw "$where references unknown role '$role'. Valid values: $($script:ValidRoles -join ', ')."
        }
    }

    $control = [pscustomobject]@{
        PSTypeName      = 'WindowsServerHardening.Control'
        Id              = [string]$Definition.Id
        Title           = [string]$Definition.Title
        Category        = [string]$Definition.Category
        Severity        = [string]$Definition.Severity
        Type            = [string]$Definition.Type
        Target          = $target
        Expected        = $Definition.Expected
        Operator        = $operator
        Minimum         = Get-OptionalValue -Table $Definition -Key 'Minimum'
        Maximum         = Get-OptionalValue -Table $Definition -Key 'Maximum'
        Allowed         = @(Get-OptionalValue -Table $Definition -Key 'Allowed')
        Parameter       = [string](Get-OptionalValue -Table $Definition -Key 'Parameter')
        Rationale       = [string]$Definition.Rationale
        Impact          = [string](Get-OptionalValue -Table $Definition -Key 'Impact')
        RebootRequired  = [bool](Get-OptionalValue -Table $Definition -Key 'RebootRequired')
        AuditOnly       = ([bool](Get-OptionalValue -Table $Definition -Key 'AuditOnly')) -or ($Definition.Type -eq 'Custom')
        OptIn           = [bool](Get-OptionalValue -Table $Definition -Key 'OptIn')
        Roles           = @(Get-OptionalValue -Table $Definition -Key 'Roles' | Where-Object { $_ })
        ExcludeRoles    = @(Get-OptionalValue -Table $Definition -Key 'ExcludeRoles' | Where-Object { $_ })
        MinimumBuild    = [int]$minimumBuild
        Benchmark       = [string](Get-OptionalValue -Table $references -Key 'Benchmark')
        MitreAttack     = @(Get-OptionalValue -Table $references -Key 'MitreAttack' | Where-Object { $_ })
        Links           = @(Get-OptionalValue -Table $references -Key 'Links' | Where-Object { $_ })
        ExpectedDisplay = $null
        Remediation     = $null
        Source          = $Source
        Order           = $Order
    }
    Update-HardeningControlText -Control $control
    return $control
}

function Get-OptionalValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Table,

        [Parameter(Mandatory)]
        [string]$Key
    )

    if ($Table.Contains($Key)) {
        return $Table[$Key]
    }
    return $null
}

function Update-HardeningControlText {
    # Recomputes the human readable expected value and remediation description, e.g. after a
    # profile parameter changed the expected value.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control
    )

    $Control.ExpectedDisplay = Get-HardeningExpectedText -Control $Control
    $Control.Remediation = Get-HardeningRemediationText -Control $Control
}

function Get-HardeningExpectedText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control
    )

    $expected = Format-HardeningValue -Value $Control.Expected
    if ($Control.Type -eq 'AuditPolicy') {
        return 'Includes ' + (Format-AuditPolicyFlag -Flag (ConvertTo-AuditPolicyFlag -Setting $Control.Expected))
    }

    switch ($Control.Operator) {
        'GreaterOrEqual' { return ">= $expected" }
        'LessOrEqual'    { return "<= $expected" }
        'Range' {
            $maximum = if ($null -ne $Control.Maximum) { $Control.Maximum } else { $Control.Expected }
            return 'Between {0} and {1}' -f $Control.Minimum, $maximum
        }
        'In'             { return 'One of: ' + (Format-HardeningValue -Value $Control.Allowed) }
        default          { return $expected }
    }
}

function Get-HardeningRemediationText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Control
    )

    $t = $Control.Target
    $value = Format-HardeningValue -Value $Control.Expected
    if ($Control.AuditOnly) {
        $manual = Get-OptionalValue -Table $t -Key 'ManualRemediation'
        if ($manual) { return "Manual: $manual" }
        return 'Manual remediation required (audit-only control).'
    }

    switch ($Control.Type) {
        'Registry'        { return 'Set registry value {0}\{1} ({2}) to {3}.' -f $t.Path, $t.Name, $t.ValueType, $value }
        'Service'         { return "Set service '$($t.Name)' startup type to $value and stop it." }
        'SmbServer'       { return "Set-SmbServerConfiguration -$($t.Property) $value" }
        'FirewallProfile' { return "Set-NetFirewallProfile -$($t.Property) $value on non-compliant profiles." }
        'FirewallRule'    { return "Create or enable inbound block rule '$($t.DisplayName)' ($($t.Protocol) $($t.LocalPort))." }
        'AuditPolicy'     { return "auditpol /set /subcategory:`"$($t.Subcategory)`" to include $(Format-AuditPolicyFlag -Flag (ConvertTo-AuditPolicyFlag -Setting $Control.Expected))." }
        'SecurityPolicy'  { return "Set local security policy $($t.Key) = $value (secedit)." }
        default           { return 'No automated remediation available.' }
    }
}

function Resolve-HardeningControlSet {
    # Applies a profile (opt-in, exclusions, audit-only overrides, parameters) and command line
    # filters to the catalog and returns the effective, ordered control list.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$ProfileData,

        [string[]]$Category,

        [string[]]$ControlId,

        [string[]]$ExcludeControlId
    )

    $catalog = @(Get-HardeningCatalog)
    $knownIds = @($catalog | ForEach-Object { $_.Id })
    foreach ($listName in @('EnableControls', 'ExcludeControls', 'AuditOnlyControls')) {
        foreach ($pattern in @($ProfileData[$listName])) {
            if ($pattern -and -not @($knownIds | Where-Object { $_ -like $pattern }).Count) {
                Write-Warning "Profile '$($ProfileData.Name)' $listName entry '$pattern' does not match any control."
            }
        }
    }

    $excluded = @($ProfileData.ExcludeControls) + @($ExcludeControlId)
    foreach ($control in $catalog) {
        $explicit = $ControlId -and (Test-HardeningIdMatch -Id $control.Id -Pattern $ControlId)
        if ($ControlId -and -not $explicit) { continue }
        if ($Category -and $Category -notcontains $control.Category) { continue }
        if ($control.OptIn -and -not $explicit -and -not (Test-HardeningIdMatch -Id $control.Id -Pattern $ProfileData.EnableControls)) { continue }
        if (Test-HardeningIdMatch -Id $control.Id -Pattern $excluded) { continue }

        $effective = $control.PSObject.Copy()
        if ($control.Parameter -and $ProfileData.Parameters.Contains($control.Parameter)) {
            $effective.Expected = $ProfileData.Parameters[$control.Parameter]
        }
        if (Test-HardeningIdMatch -Id $control.Id -Pattern $ProfileData.AuditOnlyControls) {
            $effective.AuditOnly = $true
        }
        Update-HardeningControlText -Control $effective
        $effective
    }
}
