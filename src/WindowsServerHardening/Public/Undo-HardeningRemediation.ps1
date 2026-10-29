function Undo-HardeningRemediation {
    <#
    .SYNOPSIS
        Rolls back the changes made by a remediation session.

    .DESCRIPTION
        Reads the change log of a remediation session and restores every recorded setting to the
        value it had before hardening, in reverse order. Registry values and keys that did not
        exist before are removed again, firewall rules created by the toolkit are deleted, and
        services, SMB, firewall profile and audit policy settings are set back to their previous
        values.

        Without -SessionId the most recent remediation session that has changes and has not been
        rolled back is used. Requires an elevated session.

    .PARAMETER SessionId
        ID of the remediation session to roll back (see Get-HardeningSession).

    .PARAMETER OutputPath
        Root folder that contains the sessions. Defaults to %ProgramData%\WindowsServerHardening.

    .PARAMETER Force
        Roll back without prompting for confirmation.

    .EXAMPLE
        Undo-HardeningRemediation -WhatIf

        Shows which settings of the latest remediation session would be restored.

    .EXAMPLE
        Get-HardeningSession | Where-Object Mode -eq 'Remediate'
        Undo-HardeningRemediation -SessionId 20261029-101500-a1b2c3 -Force

        Rolls back a specific session without confirmation prompts.

    .OUTPUTS
        WindowsServerHardening.RollbackResult
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType('WindowsServerHardening.RollbackResult')]
    param(
        [string]$SessionId,

        [string]$OutputPath,

        [switch]$Force
    )

    if ($Force -and -not $PSBoundParameters.ContainsKey('Confirm')) {
        $ConfirmPreference = 'None'
    }

    Assert-HardeningElevation
    $sessions = @(Get-HardeningSession -OutputPath $OutputPath | Where-Object { $_.Mode -eq 'Remediate' })
    if ($SessionId) {
        $target = $sessions | Where-Object { $_.Id -eq $SessionId } | Select-Object -First 1
        if (-not $target) {
            throw "Remediation session '$SessionId' was not found."
        }
        if ($target.RolledBack) {
            throw "Session '$SessionId' was already rolled back on $($target.RolledBackAt)."
        }
    }
    else {
        $target = $sessions | Where-Object { -not $_.RolledBack -and $_.ChangeCount -gt 0 } | Select-Object -First 1
        if (-not $target) {
            throw 'No remediation session with changes is available to roll back.'
        }
    }

    $changes = @(Read-HardeningChange -SessionPath $target.Path)
    if ($changes.Count -eq 0) {
        Write-Warning "Session $($target.Id) has no recorded changes."
        return
    }
    [array]::Reverse($changes)

    $root = Resolve-HardeningOutputRoot -Path $OutputPath
    $script:LogFile = Join-Path -Path (New-HardeningDirectory -Path (Join-Path -Path $root -ChildPath 'logs')) -ChildPath "$($target.Id)-rollback.log"
    Write-HardeningLog -Message "Rolling back session $($target.Id) ($($changes.Count) change(s))."

    $processed = 0
    $failed = 0
    foreach ($change in $changes) {
        $label = "$($change.ControlId) - $($change.Title)"
        if (-not $PSCmdlet.ShouldProcess($label, "Restore previous value ($($change.Previous.Display))")) {
            continue
        }

        $processed++
        $status = 'Failed'
        $detail = $null
        try {
            $outcome = & {
                $ConfirmPreference = 'None'
                $WhatIfPreference = $false
                Restore-ControlState -Change $change
            }
            $status = $outcome.Status
            $detail = $outcome.Detail
            Write-HardeningLog -Message "[$($change.ControlId)] $status. $detail"
        }
        catch {
            $failed++
            $detail = $_.Exception.Message
            Write-HardeningLog -Message "[$($change.ControlId)] Rollback failed: $detail" -Level Error
        }

        [pscustomobject]@{
            PSTypeName = 'WindowsServerHardening.RollbackResult'
            SessionId  = $target.Id
            ControlId  = $change.ControlId
            Title      = $change.Title
            Type       = $change.Type
            Status     = $status
            Detail     = $detail
        }
    }

    if ($processed -eq $changes.Count) {
        $values = @{ RolledBackAt = ConvertTo-HardeningIsoDate -Value (Get-Date) }
        if ($failed -eq 0) {
            $values.RolledBack = $true
            $values.Status = 'RolledBack'
        }
        else {
            $values.Status = 'RollbackIncomplete'
        }
        Update-HardeningSessionInfo -SessionPath $target.Path -Values $values
        Write-HardeningLog -Message "Rollback of session $($target.Id) finished with $failed failure(s)."
    }
}
