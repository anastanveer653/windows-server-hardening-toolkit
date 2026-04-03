#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Verify hardening status without making any changes.
    Equivalent to running: .\Harden-WindowsServer.ps1 -ReportOnly
#>

$ScriptRoot = Split-Path -Parent $PSScriptRoot
& "$ScriptRoot\Harden-WindowsServer.ps1" -ReportOnly @args
