@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Private provider functions (Set-RegistryState, Restore-ServiceState, ...) are invoked only by
        # the engine, which performs ShouldProcess once per control on behalf of the public command.
        'PSUseShouldProcessForStateChangingFunctions'
    )
    Rules        = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
        PSAvoidUsingCmdletAliases = @{
            Enable = $true
        }
    }
}
