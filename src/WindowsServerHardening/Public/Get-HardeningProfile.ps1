function Get-HardeningProfile {
    <#
    .SYNOPSIS
        Lists the built-in hardening profiles or shows the resolved settings of one profile.

    .DESCRIPTION
        Without parameters, lists the bundled profiles with their description and base profile.
        With -Name or -Path, returns the fully resolved profile (inheritance applied), including
        enabled opt-in controls, exclusions, audit-only overrides and parameters.

    .PARAMETER Name
        Name of a built-in profile to resolve.

    .PARAMETER Path
        Path to a custom JSON profile to resolve and validate.

    .EXAMPLE
        Get-HardeningProfile

        Lists the built-in profiles.

    .EXAMPLE
        (Get-HardeningProfile -Name WebServer).Parameters

        Shows the parameters (password length, log sizes, ...) used by the WebServer profile.

    .EXAMPLE
        Get-HardeningProfile -Path .\profiles\Contoso.json

        Validates a custom profile and shows the merged result.

    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding(DefaultParameterSetName = 'List')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Name', Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, ParameterSetName = 'Path')]
        [string]$Path
    )

    if ($PSCmdlet.ParameterSetName -eq 'List') {
        foreach ($file in @(Get-ChildItem -LiteralPath $script:ProfilesPath -Filter '*.json' | Sort-Object -Property Name)) {
            $data = ConvertTo-HashtableDeep -InputObject (ConvertFrom-Json -InputObject ([System.IO.File]::ReadAllText($file.FullName)))
            [pscustomobject]@{
                Name        = $data.Name
                Description = $data.Description
                Extends     = Get-OptionalValue -Table $data -Key 'Extends'
                Path        = $file.FullName
            }
        }
        return
    }

    $profileData = Get-HardeningProfileData -Name $Name -Path $Path
    return [pscustomobject]$profileData
}
