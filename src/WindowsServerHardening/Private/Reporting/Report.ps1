function ConvertTo-HardeningReportDocument {
    # Builds the stable, camelCase report schema shared by the JSON and HTML outputs. Works with live
    # run objects and with deserialized ones returned from remote sessions.
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)]
        [psobject]$Run
    )

    $system = $Run.System
    $summary = $Run.Summary
    $isSample = ($null -ne $Run.PSObject.Properties['IsSample']) -and [bool]$Run.IsSample

    $openBySeverity = [ordered]@{}
    foreach ($severity in $script:ValidSeverities) {
        $openBySeverity[$severity.ToLowerInvariant()] = [int]$summary.OpenBySeverity.$severity
    }

    $categories = foreach ($category in @($summary.Categories)) {
        [ordered]@{
            name      = $category.Name
            total     = $category.Total
            evaluated = $category.Evaluated
            compliant = $category.Compliant
            rate      = $category.Rate
        }
    }

    $results = foreach ($result in @($Run.Results)) {
        [ordered]@{
            id             = $result.Id
            title          = $result.Title
            category       = $result.Category
            severity       = $result.Severity
            status         = $result.Status
            expected       = $result.Expected
            actual         = $result.Actual
            detail         = $result.Detail
            remediation    = $result.Remediation
            auditOnly      = [bool]$result.AuditOnly
            rebootRequired = [bool]$result.RebootRequired
            rationale      = $result.Rationale
            impact         = $result.Impact
            benchmark      = $result.Benchmark
            mitreAttack    = @($result.MitreAttack)
            links          = @($result.Links)
        }
    }

    return [ordered]@{
        schemaVersion = '1.0'
        generator     = [ordered]@{
            name    = 'Windows Server Hardening Toolkit'
            version = $Run.ModuleVersion
            url     = $script:ProjectUri
        }
        isSample      = $isSample
        session       = [ordered]@{
            id              = $Run.SessionId
            mode            = $Run.Mode
            profile         = $Run.Profile
            startTime       = ConvertTo-HardeningIsoDate -Value $Run.StartTime
            endTime         = ConvertTo-HardeningIsoDate -Value $Run.EndTime
            durationSeconds = $Run.DurationSeconds
        }
        system        = [ordered]@{
            computerName      = $system.ComputerName
            domain            = $system.Domain
            role              = $system.Role
            osName            = $system.OSName
            osVersion         = $system.OSVersion
            osBuild           = $system.OSBuild
            isServer          = [bool]$system.IsServer
            lastBootTime      = ConvertTo-HardeningIsoDate -Value $system.LastBootTime
            powerShellVersion = $system.PowerShellVersion
            isElevated        = [bool]$system.IsElevated
        }
        summary       = [ordered]@{
            score          = $summary.Score
            grade          = $summary.Grade
            complianceRate = $summary.ComplianceRate
            total          = $summary.Total
            evaluated      = $summary.Evaluated
            pass           = $summary.Pass
            fixed          = $summary.Fixed
            fail           = $summary.Fail
            error          = $summary.Error
            notApplicable  = $summary.NotApplicable
            rebootRequired = [bool]$summary.RebootRequired
            openBySeverity = $openBySeverity
            categories     = @($categories)
        }
        results       = @($results)
    }
}

function ConvertTo-HardeningHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Document
    )

    $template = [System.IO.File]::ReadAllText($script:TemplatePath)
    $json = ConvertTo-Json -InputObject $Document -Depth 8 -Compress
    # Neutralise markup inside the embedded JSON so no value can terminate the <script> block. The
    # apostrophe is escaped as well so Windows PowerShell 5.1 and PowerShell 7 produce identical output.
    $json = [regex]::Replace($json, "[<>&']", { param($match) '\u{0:x4}' -f [int][char]$match.Value })
    $title = [System.Net.WebUtility]::HtmlEncode("Hardening Report - $($Document.system.computerName)")
    return $template.Replace('{{TITLE}}', $title).Replace('{{DATA}}', $json)
}

function ConvertTo-HardeningCsv {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [psobject]$Run
    )

    $rows = foreach ($result in @($Run.Results)) {
        [pscustomobject]@{
            ComputerName   = $Run.ComputerName
            SessionId      = $Run.SessionId
            Id             = $result.Id
            Title          = $result.Title
            Category       = $result.Category
            Severity       = $result.Severity
            Status         = $result.Status
            Expected       = $result.Expected
            Actual         = $result.Actual
            Detail         = $result.Detail
            Remediation    = $result.Remediation
            RebootRequired = [bool]$result.RebootRequired
            Benchmark      = $result.Benchmark
            MitreAttack    = (@($result.MitreAttack) -join ' ')
        }
    }
    return ((@($rows) | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine)
}
