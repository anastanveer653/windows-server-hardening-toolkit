function Get-HardeningProfileData {
    # Loads a profile by name (bundled profiles) or path (custom JSON) and resolves "Extends"
    # inheritance. 'Auto' selects DomainController on domain controllers, otherwise MemberServer.
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [string]$Name = 'Auto',

        [string]$Path,

        [pscustomobject]$SystemInfo,

        [int]$Depth = 0
    )

    if ($Depth -gt 5) {
        throw 'Profile inheritance is nested too deeply (maximum depth is 5). Check for circular "Extends" references.'
    }

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "Profile file not found: $Path"
        }
        $file = (Resolve-Path -LiteralPath $Path).ProviderPath
    }
    else {
        if ($Name -eq 'Auto') {
            $Name = if ($SystemInfo -and $SystemInfo.Role -eq 'DomainController') { 'DomainController' } else { 'MemberServer' }
        }
        $file = Join-Path -Path $script:ProfilesPath -ChildPath "$Name.json"
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            $available = (Get-ChildItem -LiteralPath $script:ProfilesPath -Filter '*.json' | ForEach-Object { $_.BaseName }) -join ', '
            throw "Unknown profile '$Name'. Available profiles: $available."
        }
    }

    try {
        $raw = [System.IO.File]::ReadAllText($file)
        $data = ConvertTo-HashtableDeep -InputObject (ConvertFrom-Json -InputObject $raw)
    }
    catch {
        throw "Profile '$file' is not valid JSON: $($_.Exception.Message)"
    }

    $profileData = ConvertTo-HardeningProfile -Data $data -Path $file
    if ($profileData.Extends) {
        $siblingPath = Join-Path -Path (Split-Path -Path $file -Parent) -ChildPath "$($profileData.Extends).json"
        $base = if ((Test-Path -LiteralPath $siblingPath -PathType Leaf) -and $siblingPath -ne $file) {
            Get-HardeningProfileData -Path $siblingPath -SystemInfo $SystemInfo -Depth ($Depth + 1)
        }
        else {
            Get-HardeningProfileData -Name $profileData.Extends -SystemInfo $SystemInfo -Depth ($Depth + 1)
        }
        $profileData = Merge-HardeningProfile -Base $base -Child $profileData
    }
    return $profileData
}

function ConvertTo-HardeningProfile {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Data,

        [string]$Path
    )

    if (-not $Data.Contains('Name') -or -not $Data.Name) {
        throw "Profile '$Path' must define a Name."
    }

    $parameters = [ordered]@{}
    if ($Data.Contains('Parameters') -and $Data.Parameters) {
        foreach ($key in $Data.Parameters.Keys) {
            $parameters[$key] = $Data.Parameters[$key]
        }
    }

    return [ordered]@{
        Name              = [string]$Data.Name
        Description       = [string](Get-OptionalValue -Table $Data -Key 'Description')
        Extends           = [string](Get-OptionalValue -Table $Data -Key 'Extends')
        Path              = $Path
        EnableControls    = @(Get-OptionalValue -Table $Data -Key 'EnableControls' | Where-Object { $_ })
        ExcludeControls   = @(Get-OptionalValue -Table $Data -Key 'ExcludeControls' | Where-Object { $_ })
        AuditOnlyControls = @(Get-OptionalValue -Table $Data -Key 'AuditOnlyControls' | Where-Object { $_ })
        Parameters        = $parameters
    }
}

function Merge-HardeningProfile {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Base,

        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Child
    )

    $parameters = [ordered]@{}
    foreach ($key in $Base.Parameters.Keys) { $parameters[$key] = $Base.Parameters[$key] }
    foreach ($key in $Child.Parameters.Keys) { $parameters[$key] = $Child.Parameters[$key] }

    return [ordered]@{
        Name              = $Child.Name
        Description       = if ($Child.Description) { $Child.Description } else { $Base.Description }
        Extends           = $Child.Extends
        Path              = $Child.Path
        EnableControls    = @(@($Base.EnableControls) + @($Child.EnableControls) | Select-Object -Unique)
        ExcludeControls   = @(@($Base.ExcludeControls) + @($Child.ExcludeControls) | Select-Object -Unique)
        AuditOnlyControls = @(@($Base.AuditOnlyControls) + @($Child.AuditOnlyControls) | Select-Object -Unique)
        Parameters        = $parameters
    }
}
