@{
    # Order matters: the lockout threshold must be non-zero before a lockout duration can be set,
    # and the reset window must not exceed the duration.
    Controls = @(
        @{
            Id         = 'ACCT-001'
            Title      = 'Minimum password length'
            Category   = 'AccountPolicy'
            Severity   = 'High'
            Type       = 'SecurityPolicy'
            Target     = @{ Key = 'MinimumPasswordLength' }
            Expected   = 14
            Operator   = 'GreaterOrEqual'
            Parameter  = 'MinimumPasswordLength'
            Rationale  = 'Password length is the strongest single factor against offline cracking and guessing attacks.'
            Impact     = 'Applies at the next password change of local accounts. On domain members, domain password policy applies to domain accounts.'
            References = @{
                Benchmark   = 'CIS: Minimum password length = 14 or more character(s)'
                MitreAttack = @('T1110', 'T1110.002')
            }
        }
        @{
            Id         = 'ACCT-002'
            Title      = 'Password history size'
            Category   = 'AccountPolicy'
            Severity   = 'Medium'
            Type       = 'SecurityPolicy'
            Target     = @{ Key = 'PasswordHistorySize' }
            Expected   = 24
            Operator   = 'GreaterOrEqual'
            Parameter  = 'PasswordHistorySize'
            Rationale  = 'Stops users from cycling back to previously compromised passwords.'
            References = @{
                Benchmark   = 'CIS: Enforce password history = 24 or more password(s)'
                MitreAttack = @('T1110')
            }
        }
        @{
            Id         = 'ACCT-003'
            Title      = 'Maximum password age'
            Category   = 'AccountPolicy'
            Severity   = 'Medium'
            Type       = 'SecurityPolicy'
            Target     = @{ Key = 'MaximumPasswordAge' }
            Expected   = 365
            Operator   = 'Range'
            Minimum    = 1
            Parameter  = 'MaximumPasswordAge'
            Rationale  = 'Passwords that never expire (value -1 or 0) remain valid indefinitely after a silent compromise.'
            References = @{
                Benchmark   = 'CIS: Maximum password age = 365 or fewer days, but not 0'
                MitreAttack = @('T1078')
            }
        }
        @{
            Id         = 'ACCT-004'
            Title      = 'Minimum password age'
            Category   = 'AccountPolicy'
            Severity   = 'Low'
            Type       = 'SecurityPolicy'
            Target     = @{ Key = 'MinimumPasswordAge' }
            Expected   = 1
            Operator   = 'GreaterOrEqual'
            Parameter  = 'MinimumPasswordAge'
            Rationale  = 'Without a minimum age, users can immediately cycle through the password history and reuse their old password.'
            References = @{
                Benchmark   = 'CIS: Minimum password age = 1 or more day(s)'
                MitreAttack = @('T1110')
            }
        }
        @{
            Id         = 'ACCT-005'
            Title      = 'Passwords must meet complexity requirements'
            Category   = 'AccountPolicy'
            Severity   = 'High'
            Type       = 'SecurityPolicy'
            Target     = @{ Key = 'PasswordComplexity' }
            Expected   = 1
            Rationale  = 'Complexity rules prevent dictionary words and account names from being used as passwords.'
            References = @{
                Benchmark   = 'CIS: Password must meet complexity requirements = Enabled'
                MitreAttack = @('T1110.001', 'T1110.003')
            }
        }
        @{
            Id         = 'ACCT-006'
            Title      = 'Passwords are not stored using reversible encryption'
            Category   = 'AccountPolicy'
            Severity   = 'High'
            Type       = 'SecurityPolicy'
            Target     = @{ Key = 'ClearTextPassword' }
            Expected   = 0
            Rationale  = 'Reversible encryption is equivalent to storing passwords in cleartext.'
            References = @{
                Benchmark   = 'CIS: Store passwords using reversible encryption = Disabled'
                MitreAttack = @('T1003')
            }
        }
        @{
            Id         = 'ACCT-007'
            Title      = 'Account lockout threshold'
            Category   = 'AccountPolicy'
            Severity   = 'High'
            Type       = 'SecurityPolicy'
            Target     = @{ Key = 'LockoutBadCount' }
            Expected   = 5
            Operator   = 'Range'
            Minimum    = 1
            Parameter  = 'LockoutThreshold'
            Rationale  = 'A threshold of 0 never locks accounts, allowing unlimited online password guessing.'
            Impact     = 'Accounts lock after repeated failures, which can be abused for denial of service against known account names.'
            References = @{
                Benchmark   = 'CIS: Account lockout threshold = 5 or fewer invalid logon attempt(s), but not 0'
                MitreAttack = @('T1110.001', 'T1110.003')
            }
        }
        @{
            Id         = 'ACCT-008'
            Title      = 'Account lockout duration'
            Category   = 'AccountPolicy'
            Severity   = 'Medium'
            Type       = 'SecurityPolicy'
            Target     = @{ Key = 'LockoutDuration' }
            Expected   = 15
            Operator   = 'GreaterOrEqual'
            Parameter  = 'LockoutDuration'
            Rationale  = 'A sufficient lockout duration slows down brute-force attacks to an impractical rate.'
            References = @{
                Benchmark   = 'CIS: Account lockout duration = 15 or more minute(s)'
                MitreAttack = @('T1110')
            }
        }
        @{
            Id         = 'ACCT-009'
            Title      = 'Reset account lockout counter after'
            Category   = 'AccountPolicy'
            Severity   = 'Medium'
            Type       = 'SecurityPolicy'
            Target     = @{ Key = 'ResetLockoutCount' }
            Expected   = 15
            Operator   = 'GreaterOrEqual'
            Parameter  = 'ResetLockoutCount'
            Rationale  = 'A short observation window lets attackers spread guesses just below the lockout threshold.'
            Impact     = 'Must be less than or equal to the lockout duration, otherwise secedit rejects the policy.'
            References = @{
                Benchmark   = 'CIS: Reset account lockout counter after = 15 or more minute(s)'
                MitreAttack = @('T1110.003')
            }
        }
        @{
            Id         = 'ACCT-010'
            Title      = 'Built-in Guest account is disabled'
            Category   = 'AccountPolicy'
            Severity   = 'High'
            Type       = 'SecurityPolicy'
            Target     = @{ Key = 'EnableGuestAccount' }
            Expected   = 0
            Rationale  = 'The Guest account allows unauthenticated access to the server and its shares.'
            References = @{
                Benchmark   = 'CIS: Accounts: Guest account status = Disabled'
                MitreAttack = @('T1078.001')
            }
        }
    )
}
