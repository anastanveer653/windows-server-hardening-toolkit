function Get-HardeningControl {
    <#
    .SYNOPSIS
        Lists the controls in the hardening catalog.

    .DESCRIPTION
        Returns control definitions with their category, severity, expected value, remediation,
        rationale and references (CIS recommendation and MITRE ATT&CK techniques). With
        -ProfileName or -ProfilePath, returns the effective control set of that profile, with
        profile parameters applied to the expected values.

    .PARAMETER Id
        Return only these control IDs. Wildcards are supported.

    .PARAMETER Category
        Return only controls in these categories.

    .PARAMETER Severity
        Return only controls with these severities.

    .PARAMETER ProfileName
        Return the effective controls of a built-in profile.

    .PARAMETER ProfilePath
        Return the effective controls of a custom JSON profile.

    .EXAMPLE
        Get-HardeningControl | Group-Object Category | Select-Object Name, Count

        Shows how many controls each category contains.

    .EXAMPLE
        Get-HardeningControl -Id 'AUTH-*' | Format-List Id, Title, Expected, Rationale, MitreAttack

        Shows details of the authentication controls.

    .EXAMPLE
        Get-HardeningControl -ProfileName DomainController -Severity Critical, High

        Lists the critical and high severity controls that the DomainController profile evaluates.

    .OUTPUTS
        WindowsServerHardening.Control
    #>
    [CmdletBinding(DefaultParameterSetName = 'Catalog')]
    [OutputType('WindowsServerHardening.Control')]
    param(
        [string[]]$Id,

        [string[]]$Category,

        [ValidateSet('Critical', 'High', 'Medium', 'Low')]
        [string[]]$Severity,

        [Parameter(Mandatory, ParameterSetName = 'Profile')]
        [Alias('Profile')]
        [string]$ProfileName,

        [Parameter(Mandatory, ParameterSetName = 'ProfilePath')]
        [string]$ProfilePath
    )

    $controls = if ($PSCmdlet.ParameterSetName -eq 'Catalog') {
        Get-HardeningCatalog
    }
    else {
        $profileData = Get-HardeningProfileData -Name $ProfileName -Path $ProfilePath -SystemInfo (Get-HardeningSystemInfo)
        Resolve-HardeningControlSet -ProfileData $profileData
    }

    foreach ($control in @($controls)) {
        if ($Id -and -not (Test-HardeningIdMatch -Id $control.Id -Pattern $Id)) { continue }
        if ($Category -and $Category -notcontains $control.Category) { continue }
        if ($Severity -and $Severity -notcontains $control.Severity) { continue }
        $control
    }
}
