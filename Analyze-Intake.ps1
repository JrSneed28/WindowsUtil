#Requires -Version 5.1

<#
.SYNOPSIS
    WinCare Phase 1 analyzer for Collector intake JSON.

.DESCRIPTION
    Reads a Collector intake JSON file, generates prioritized findings,
    creates a tailored WinCare config from the base config template,
    and writes a remediation plan in Markdown.

    This script is intentionally standalone and read-only with respect to
    system state. It only reads input files and writes analysis artifacts.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$IntakePath,

    [Parameter()]
    [string]$BaseConfigPath = (Join-Path $PSScriptRoot 'WinCare.config.json'),

    [Parameter()]
    [string]$OutputConfigPath,

    [Parameter()]
    [string]$RemediationPlanPath,

    [Parameter()]
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-AnalyzeLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$ts] [$Level] $Message"
    switch ($Level) {
        'ERROR' { Write-Error $line }
        'WARN'  { Write-Warning $line }
        default { Write-Output $line }
    }
}

function Save-Utf8BomFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    $parent = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }

    [System.IO.File]::WriteAllText(
        $Path,
        $Content,
        [System.Text.UTF8Encoding]::new($true)
    )
}

function ConvertTo-Hashtable {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $hash = @{}
        foreach ($key in $InputObject.Keys) {
            $hash[$key] = ConvertTo-Hashtable -InputObject $InputObject[$key]
        }
        return $hash
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        $items = @()
        foreach ($item in $InputObject) {
            $items += @(ConvertTo-Hashtable -InputObject $item)
        }
        return $items
    }

    if ($InputObject -is [pscustomobject]) {
        $hash = @{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            $hash[$prop.Name] = ConvertTo-Hashtable -InputObject $prop.Value
        }
        return $hash
    }

    return $InputObject
}

function Set-NestedValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Target,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        $Value
    )

    $segments = $Path -split '\.'
    if ($segments.Count -lt 1) {
        throw "Invalid path: '$Path'"
    }

    $cursor = $Target
    for ($i = 0; $i -lt ($segments.Count - 1); $i++) {
        $segment = $segments[$i]
        if (-not $cursor.ContainsKey($segment) -or $null -eq $cursor[$segment]) {
            $cursor[$segment] = @{}
        }

        if (-not ($cursor[$segment] -is [hashtable])) {
            $cursor[$segment] = ConvertTo-Hashtable -InputObject $cursor[$segment]
        }

        $cursor = $cursor[$segment]
    }

    $cursor[$segments[-1]] = $Value
}

function Find-Section {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Intake,

        [Parameter(Mandatory = $true)]
        [string[]]$Candidates
    )

    foreach ($key in $Candidates) {
        if ($Intake.ContainsKey($key)) {
            return $Intake[$key]
        }
    }
    return $null
}

function Get-CollectorData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Section,

        [Parameter(Mandatory = $true)]
        [string]$Key
    )

    if (-not $Section.ContainsKey($Key) -or $null -eq $Section[$Key]) {
        return $null
    }

    $node = ConvertTo-Hashtable -InputObject $Section[$Key]
    if ($node -isnot [hashtable]) {
        return $null
    }

    if ($node.ContainsKey('Status') -and $node.Status -eq 'OK' -and $node.ContainsKey('Data')) {
        return $node.Data
    }

    if ($node.ContainsKey('Data')) {
        return $node.Data
    }

    return $node
}

function New-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter()]
        [string[]]$Evidence = @(),

        [Parameter()]
        [string[]]$RecommendedActions = @(),

        [Parameter()]
        [hashtable[]]$ConfigChanges = @(),

        [Parameter()]
        [hashtable[]]$Citations = @()
    )

    return [ordered]@{
        Id                 = $Id
        Severity           = $Severity
        Category           = $Category
        Title              = $Title
        Description        = $Description
        Evidence           = @($Evidence)
        RecommendedActions = @($RecommendedActions)
        ConfigChanges      = @($ConfigChanges)
        Citations          = @($Citations)
    }
}

function Get-SeverityWeight {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Severity)

    switch ($Severity) {
        'Critical' { return 5 }
        'High'     { return 4 }
        'Medium'   { return 3 }
        'Low'      { return 2 }
        default    { return 1 }
    }
}

function Invoke-AnalyzeSectionA {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Section)

    $findings = @()

    $edition = Get-CollectorData -Section $Section -Key 'Edition'
    $domain = Get-CollectorData -Section $Section -Key 'DomainEnrollment'
    $hardware = Get-CollectorData -Section $Section -Key 'Hardware'
    $disk = Get-CollectorData -Section $Section -Key 'DiskSpace'

    if ($edition -and $edition.IsLTSC) {
        $findings += New-Finding -Id 'A-LTSC-01' -Severity 'Medium' -Category 'Compatibility' -Title 'LTSC edition detected' -Description 'Windows LTSC detected. Consumer feature changes should remain conservative.' -Evidence @("Edition: $($edition.ProductName)") -RecommendedActions @('Keep debloat and gaming modules disabled unless explicitly required.') -ConfigChanges @(
            @{ Path = 'modules.debloat.enabled'; Value = $false; Reason = 'LTSC conservative defaults' }
            @{ Path = 'modules.gamingOptimize.enabled'; Value = $false; Reason = 'LTSC conservative defaults' }
        ) -Citations @(
            @{ Tier = 'Microsoft Learn'; Source = 'Windows servicing channels'; Url = 'https://learn.microsoft.com/windows/deployment/update/waas-overview' }
        )
    }

    if ($domain -and ($domain.IsDomainJoined -or $domain.IsIntuneManaged -or $domain.IsEntraJoined)) {
        $findings += New-Finding -Id 'A-ENTERPRISE-01' -Severity 'High' -Category 'Policy' -Title 'Enterprise management signals detected' -Description 'Domain/Entra/Intune management indicates policy-controlled endpoints.' -Evidence @(
            "IsDomainJoined=$($domain.IsDomainJoined)"
            "IsEntraJoined=$($domain.IsEntraJoined)"
            "IsIntuneManaged=$($domain.IsIntuneManaged)"
        ) -RecommendedActions @(
            'Avoid policy-sensitive tweaks on managed devices.'
            'Coordinate update remediations with enterprise management owners.'
        ) -ConfigChanges @(
            @{ Path = 'modules.debloat.enabled'; Value = $false; Reason = 'Managed endpoint safety' }
            @{ Path = 'modules.gamingOptimize.enabled'; Value = $false; Reason = 'Managed endpoint safety' }
            @{ Path = 'modules.windowsUpdate.resetComponents'; Value = $false; Reason = 'Policy-managed update stack' }
        ) -Citations @(
            @{ Tier = 'Microsoft Learn'; Source = 'Windows client management overview'; Url = 'https://learn.microsoft.com/windows/client-management/' }
        )
    }

    if ($hardware -and $hardware.IsVM) {
        $findings += New-Finding -Id 'A-VM-01' -Severity 'Low' -Category 'Compatibility' -Title 'Virtual machine detected' -Description 'VM environments usually do not benefit from gaming performance changes.' -Evidence @("Model: $($hardware.Model)") -RecommendedActions @('Skip gaming optimization module for virtualized systems.') -ConfigChanges @(
            @{ Path = 'modules.gamingOptimize.enabled'; Value = $false; Reason = 'VM profile' }
        ) -Citations @(
            @{ Tier = 'Microsoft Learn'; Source = 'Hyper-V best practices'; Url = 'https://learn.microsoft.com/windows-server/virtualization/hyper-v/' }
        )
    }

    if ($hardware -and $hardware.IsLaptop) {
        $findings += New-Finding -Id 'A-LAPTOP-01' -Severity 'Low' -Category 'Power' -Title 'Laptop profile detected' -Description 'Laptop power and thermal constraints may make aggressive performance tuning undesirable.' -Evidence @("IsLaptop=$($hardware.IsLaptop)") -RecommendedActions @('Leave high-performance power plan toggles disabled unless user opts in.') -ConfigChanges @(
            @{ Path = 'modules.gamingOptimize.setHighPerformancePower'; Value = $false; Reason = 'Battery/thermal safety' }
        ) -Citations @(
            @{ Tier = 'Microsoft Learn'; Source = 'Power plans in Windows'; Url = 'https://learn.microsoft.com/windows-hardware/design/device-experiences/powercfg-command-line-options' }
        )
    }

    if ($disk) {
        $lowSpace = @($disk | Where-Object { $_.LowSpace -eq $true -or $_.Free_GB -lt 10 })
        if ($lowSpace.Count -gt 0) {
            $drives = $lowSpace | ForEach-Object { "$($_.Drive) ($($_.Free_GB) GB free)" }
            $findings += New-Finding -Id 'A-DISK-01' -Severity 'High' -Category 'Health' -Title 'Low disk space detected' -Description 'Low free space can cause update and servicing failures.' -Evidence $drives -RecommendedActions @(
                'Free disk space before running heavy repair operations.'
                'Prioritize storage cleanup before optional modules.'
            ) -ConfigChanges @(
                @{ Path = 'modules.repairHealth.runDISMRestoreHealth'; Value = $false; Reason = 'Reduce risk under low disk conditions' }
                @{ Path = 'modules.gamingOptimize.enabled'; Value = $false; Reason = 'Defer optional tuning until storage pressure is resolved' }
            ) -Citations @(
                @{ Tier = 'Microsoft Learn'; Source = 'DISM repair image'; Url = 'https://learn.microsoft.com/windows-hardware/manufacture/desktop/dism-image-management-command-line-options-s14?view=windows-11' }
            )
        }
    }

    return @($findings)
}

function Invoke-AnalyzeSectionB {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Section)

    $findings = @()

    $dism = Get-CollectorData -Section $Section -Key 'DISM'
    $sfc = Get-CollectorData -Section $Section -Key 'SFC'
    $pendingReboot = Get-CollectorData -Section $Section -Key 'PendingReboot'
    $events = Get-CollectorData -Section $Section -Key 'EventLogSummary'
    $diskHealth = Get-CollectorData -Section $Section -Key 'DiskHealth'

    if ($pendingReboot -and $pendingReboot.AnyPending) {
        $reasons = @()
        foreach ($k in @('ComponentBasedServicing', 'WindowsUpdate', 'PendingFileRename', 'JoinDomain')) {
            if ($pendingReboot.ContainsKey($k) -and $pendingReboot[$k]) {
                $reasons += $k
            }
        }

        $findings += New-Finding -Id 'B-REBOOT-01' -Severity 'High' -Category 'Health' -Title 'Pending reboot detected' -Description 'A pending reboot can block repair and update workflows.' -Evidence @("Reasons: $($reasons -join ', ')") -RecommendedActions @('Reboot before running remediation modules.') -ConfigChanges @(
            @{ Path = 'modules.windowsUpdate.resetComponents'; Value = $false; Reason = 'Do not reset before reboot' }
            @{ Path = 'modules.repairHealth.runDISMRestoreHealth'; Value = $false; Reason = 'Delay deeper servicing until post-reboot' }
        ) -Citations @(
            @{ Tier = 'Microsoft Learn'; Source = 'Windows Update troubleshooting guidance'; Url = 'https://learn.microsoft.com/windows/deployment/update/windows-update-resources' }
        )
    }

    if ($dism -and $dism.NeedsRepair) {
        $findings += New-Finding -Id 'B-DISM-01' -Severity 'Critical' -Category 'RepairHealth' -Title 'Component store indicates repair needed' -Description 'DISM ScanHealth indicates servicing corruption requiring restore-health remediation.' -Evidence @('DISM NeedsRepair=true') -RecommendedActions @(
            'Enable DISM RestoreHealth sequence.'
            'Run SFC after DISM to repair file-level integrity.'
        ) -ConfigChanges @(
            @{ Path = 'modules.repairHealth.enabled'; Value = $true; Reason = 'Repair required' }
            @{ Path = 'modules.repairHealth.runDISMScanHealth'; Value = $true; Reason = 'Validate corruption before restoration' }
            @{ Path = 'modules.repairHealth.runDISMRestoreHealth'; Value = $true; Reason = 'Repair required' }
            @{ Path = 'modules.repairHealth.runSFC'; Value = $true; Reason = 'Post-DISM validation' }
        ) -Citations @(
            @{ Tier = 'Microsoft Learn'; Source = 'Repair a Windows image'; Url = 'https://learn.microsoft.com/windows-hardware/manufacture/desktop/repair-a-windows-image' }
            @{ Tier = 'Microsoft Learn'; Source = 'SFC command'; Url = 'https://learn.microsoft.com/windows-server/administration/windows-commands/sfc' }
        )
    }

    if ($sfc -and $sfc.LastSFCResult -eq 'CorruptUnfixed') {
        $findings += New-Finding -Id 'B-SFC-01' -Severity 'Critical' -Category 'RepairHealth' -Title 'SFC reports unfixable corruption' -Description 'SFC identified corrupt files it could not repair.' -Evidence @('LastSFCResult=CorruptUnfixed') -RecommendedActions @(
            'Run DISM RestoreHealth then rerun SFC.'
            'Review CBS.log if corruption persists.'
        ) -ConfigChanges @(
            @{ Path = 'modules.repairHealth.enabled'; Value = $true; Reason = 'Corruption remediation' }
            @{ Path = 'modules.repairHealth.runDISMRestoreHealth'; Value = $true; Reason = 'SFC could not repair files' }
            @{ Path = 'modules.repairHealth.runSFC'; Value = $true; Reason = 'Validate post-repair state' }
        ) -Citations @(
            @{ Tier = 'Microsoft Learn'; Source = 'Use DISM and SFC together'; Url = 'https://support.microsoft.com/windows/use-the-system-file-checker-tool-to-repair-missing-or-corrupted-system-files-79aa86cb-ca52-166a-92a3-966e85d4094e' }
        )
    }

    if ($events) {
        $wuSources = @('WindowsUpdateClient', 'BITS', 'Service Control Manager')
        $systemHits = @($events.SystemErrorSources | Where-Object { $_.Source -in $wuSources -or $_.Sample -match 'update|servicing|wuauserv|bits' })
        if ($systemHits.Count -gt 0) {
            $evidence = $systemHits | Select-Object -First 5 | ForEach-Object { "$($_.Source) ($($_.Count))" }
            $findings += New-Finding -Id 'B-WU-01' -Severity 'Medium' -Category 'WindowsUpdate' -Title 'Windows Update related errors observed' -Description 'Event logs indicate update pipeline instability.' -Evidence $evidence -RecommendedActions @(
                'Enable Windows Update diagnostics.'
                'Only run reset-components when failures persist after standard remediation.'
            ) -ConfigChanges @(
                @{ Path = 'modules.windowsUpdate.enabled'; Value = $true; Reason = 'Update diagnostics needed' }
                @{ Path = 'modules.windowsUpdate.diagnosePending'; Value = $true; Reason = 'Gather actionable detail' }
            ) -Citations @(
                @{ Tier = 'Microsoft Learn'; Source = 'Windows update troubleshooting'; Url = 'https://learn.microsoft.com/troubleshoot/windows-client/installing-updates-features-roles/troubleshoot-windows-update-issues' }
            )
        }
    }

    if ($diskHealth) {
        $failingDisks = @(
            $diskHealth | Where-Object {
                ($_ -is [hashtable]) -and
                $_.ContainsKey('PredictFailure') -and
                ($_.PredictFailure -eq $true)
            }
        )
        if ($failingDisks.Count -gt 0) {
            $evidence = $failingDisks | ForEach-Object { "$($_.InstanceName) Reason=$($_.Reason)" }
            $findings += New-Finding -Id 'B-DISK-02' -Severity 'Critical' -Category 'Hardware' -Title 'Predictive disk failure reported' -Description 'SMART indicates at least one disk predicts failure.' -Evidence $evidence -RecommendedActions @(
                'Immediately back up data.'
                'Do not run heavy optimization workflows until storage is replaced.'
            ) -ConfigChanges @(
                @{ Path = 'modules.gamingOptimize.enabled'; Value = $false; Reason = 'Hardware risk state' }
                @{ Path = 'modules.debloat.enabled'; Value = $false; Reason = 'Prioritize data safety' }
            ) -Citations @(
                @{ Tier = 'Microsoft Learn'; Source = 'Storage reliability guidance'; Url = 'https://learn.microsoft.com/windows-hardware/drivers/storage/' }
            )
        }
    }

    return @($findings)
}

function Invoke-AnalyzeSectionC {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Section)

    $findings = @()

    $appx = @(Get-CollectorData -Section $Section -Key 'AppXPackages')
    $programs = @(Get-CollectorData -Section $Section -Key 'InstalledPrograms')
    $startup = @(Get-CollectorData -Section $Section -Key 'StartupItems')
    $winget = Get-CollectorData -Section $Section -Key 'WinGet'

    if ($startup.Count -ge 20) {
        $findings += New-Finding -Id 'C-STARTUP-01' -Severity 'Medium' -Category 'Performance' -Title 'High startup load detected' -Description 'Startup entry count is high and may degrade boot/login performance.' -Evidence @("StartupItems=$($startup.Count)") -RecommendedActions @(
            'Review startup entries and disable non-essential launch items.'
            'Use gaming optimize startup controls only after manual review.'
        ) -ConfigChanges @(
            @{ Path = 'modules.gamingOptimize.enabled'; Value = $true; Reason = 'Startup optimization candidate' }
            @{ Path = 'modules.gamingOptimize.disableStartupItems'; Value = $true; Reason = 'High startup load' }
        ) -Citations @(
            @{ Tier = 'Microsoft Learn'; Source = 'Manage startup apps in Windows'; Url = 'https://support.microsoft.com/windows/configure-startup-applications-in-windows-115a420a-0bff-4a6f-90e0-1934c844e473' }
        )
    }

    if ($winget -and $winget.Available -eq $false) {
        $findings += New-Finding -Id 'C-WINGET-01' -Severity 'Medium' -Category 'AppUpdates' -Title 'WinGet is unavailable' -Description 'Package manager is unavailable, so automated third-party app updates are limited.' -Evidence @('WinGet.Available=false') -RecommendedActions @('Install/repair App Installer from Microsoft Store to restore WinGet support.') -ConfigChanges @(
            @{ Path = 'modules.appUpdates.useWinGet'; Value = $false; Reason = 'WinGet unavailable' }
            @{ Path = 'modules.appUpdates.enabled'; Value = $false; Reason = 'No supported update backend' }
        ) -Citations @(
            @{ Tier = 'Microsoft Learn'; Source = 'Windows Package Manager'; Url = 'https://learn.microsoft.com/windows/package-manager/winget/' }
        )
    }

    $bloatPatterns = @(
        'Candy Crush',
        'Facebook',
        'Spotify',
        'TikTok',
        'Disney',
        'Netflix',
        'XboxGameOverlay',
        'Solitaire'
    )

    $matchedBloat = @()
    foreach ($pkg in $appx) {
        foreach ($pattern in $bloatPatterns) {
            if ($pkg.Name -match [regex]::Escape($pattern)) {
                $matchedBloat += $pkg.Name
                break
            }
        }
    }

    if ($matchedBloat.Count -ge 3) {
        $findings += New-Finding -Id 'C-BLOAT-01' -Severity 'Low' -Category 'Debloat' -Title 'Multiple consumer packages detected' -Description 'Several known consumer-oriented packages are installed and may be removable by policy.' -Evidence @($matchedBloat | Select-Object -First 8) -RecommendedActions @(
            'Enable allowlist-based debloat mode only after reviewing package list.'
            'Keep hardcoded exclusions to protect critical components.'
        ) -ConfigChanges @(
            @{ Path = 'modules.debloat.enabled'; Value = $true; Reason = 'Potential package cleanup opportunity' }
            @{ Path = 'modules.debloat.mode'; Value = 'allowlist'; Reason = 'Conservative debloat strategy' }
            @{ Path = 'modules.debloat.removeMicrosoftConsumerApps'; Value = $true; Reason = 'Bloat evidence observed' }
        ) -Citations @(
            @{ Tier = 'Microsoft Learn'; Source = 'Appx package cmdlets'; Url = 'https://learn.microsoft.com/powershell/module/appx/' }
        )
    }

    if ($programs.Count -ge 200) {
        $findings += New-Finding -Id 'C-PROGRAMS-01' -Severity 'Low' -Category 'Inventory' -Title 'Large installed software footprint' -Description 'High installed-program volume increases update and maintenance burden.' -Evidence @("InstalledPrograms=$($programs.Count)") -RecommendedActions @('Prioritize app update pass and remove obsolete software manually.') -ConfigChanges @(
            @{ Path = 'modules.appUpdates.enabled'; Value = $true; Reason = 'High maintenance footprint' }
            @{ Path = 'modules.appUpdates.upgradeAll'; Value = $false; Reason = 'Keep manual approval loop' }
        ) -Citations @(
            @{ Tier = 'Microsoft Learn'; Source = 'WinGet upgrade'; Url = 'https://learn.microsoft.com/windows/package-manager/winget/upgrade' }
        )
    }

    return @($findings)
}

function Invoke-AnalyzeSectionD {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Section)

    $findings = @()

    $defender = Get-CollectorData -Section $Section -Key 'Defender'
    $thirdPartyAv = Get-CollectorData -Section $Section -Key 'ThirdPartyAV'
    $firewall = @(Get-CollectorData -Section $Section -Key 'Firewall')

    if ($defender -is [hashtable]) {
        $amServiceEnabled = $null
        $realTimeProtectionEnabled = $null

        if ($defender.ContainsKey('AMServiceEnabled')) {
            $amServiceEnabled = [bool]$defender.AMServiceEnabled
        }
        if ($defender.ContainsKey('RealTimeProtectionEnabled')) {
            $realTimeProtectionEnabled = [bool]$defender.RealTimeProtectionEnabled
        }

        if (($null -ne $amServiceEnabled -and -not $amServiceEnabled) -or ($null -ne $realTimeProtectionEnabled -and -not $realTimeProtectionEnabled)) {
            $findings += New-Finding -Id 'D-DEFENDER-01' -Severity 'Critical' -Category 'Security' -Title 'Defender protection is reduced' -Description 'Core Microsoft Defender services/protections are disabled.' -Evidence @(
                "AMServiceEnabled=$amServiceEnabled"
                "RealTimeProtectionEnabled=$realTimeProtectionEnabled"
            ) -RecommendedActions @(
                'Re-enable Defender protections unless another managed AV policy is in place.'
                'Run quick scan after protections are restored.'
            ) -ConfigChanges @(
                @{ Path = 'modules.securityScan.enabled'; Value = $true; Reason = 'Security remediation needed' }
                @{ Path = 'modules.securityScan.checkDefenderStatus'; Value = $true; Reason = 'Validate protection state' }
                @{ Path = 'modules.securityScan.runQuickScan'; Value = $true; Reason = 'Immediate security signal' }
            ) -Citations @(
                @{ Tier = 'Microsoft Learn'; Source = 'Microsoft Defender Antivirus in Windows'; Url = 'https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows' }
            )
        }

        $signatureAgeDays = $null
        if ($defender.ContainsKey('AntivirusSignatureAgeDays') -and $null -ne $defender.AntivirusSignatureAgeDays) {
            try {
                $signatureAgeDays = [int]$defender.AntivirusSignatureAgeDays
            }
            catch {
                $signatureAgeDays = $null
            }
        }

        if ($null -ne $signatureAgeDays -and $signatureAgeDays -ge 7) {
            $findings += New-Finding -Id 'D-DEFENDER-02' -Severity 'High' -Category 'Security' -Title 'Defender signatures are stale' -Description 'Antivirus signatures are older than recommended baseline.' -Evidence @("AntivirusSignatureAgeDays=$signatureAgeDays") -RecommendedActions @('Update definitions before running scans.') -ConfigChanges @(
                @{ Path = 'modules.securityScan.updateDefinitions'; Value = $true; Reason = 'Outdated signatures' }
                @{ Path = 'modules.securityScan.runQuickScan'; Value = $true; Reason = 'Post-update scan' }
            ) -Citations @(
                @{ Tier = 'Microsoft Learn'; Source = 'Manage Defender updates'; Url = 'https://learn.microsoft.com/defender-endpoint/manage-protection-updates-microsoft-defender-antivirus' }
            )
        }
    }

    $hasThirdPartyAV = $false
    if ($thirdPartyAv -is [hashtable] -and $thirdPartyAv.ContainsKey('HasThirdPartyAV')) {
        $hasThirdPartyAV = [bool]$thirdPartyAv.HasThirdPartyAV
    }

    if ($hasThirdPartyAV) {
        $vendors = @()
        if ($thirdPartyAv.ContainsKey('Products')) {
            $vendors = @($thirdPartyAv.Products)
        }
        if ($vendors.Count -eq 0) {
            $vendors = @('Unknown third-party AV')
        }

        $findings += New-Finding -Id 'D-AV-01' -Severity 'Medium' -Category 'Security' -Title 'Third-party AV detected' -Description 'Third-party antimalware appears installed, so scan orchestration should avoid conflicting behavior.' -Evidence @($vendors | ForEach-Object { "AV: $_" }) -RecommendedActions @(
            'Limit automated Defender full scans if another enterprise AV is active.'
            'Keep Defender status checks enabled for visibility.'
        ) -ConfigChanges @(
            @{ Path = 'modules.securityScan.runFullScan'; Value = $false; Reason = 'Avoid duplicate heavy scanning with third-party AV' }
            @{ Path = 'modules.securityScan.runQuickScan'; Value = $false; Reason = 'Avoid overlap with non-Defender primary AV' }
        ) -Citations @(
            @{ Tier = 'Microsoft Learn'; Source = 'Defender coexistence with third-party solutions'; Url = 'https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-compatibility' }
        )
    }

    if ($firewall.Count -gt 0) {
        $disabledProfiles = @(
            $firewall | Where-Object {
                ($_ -is [hashtable]) -and
                $_.ContainsKey('Enabled') -and
                ($_.Enabled -eq $false)
            }
        )
        if ($disabledProfiles.Count -gt 0) {
            $evidence = $disabledProfiles | ForEach-Object {
                $profileName = if ($_.ContainsKey('Profile')) { $_.Profile } else { 'Unknown' }
                "$profileName=Disabled"
            }
            $findings += New-Finding -Id 'D-FW-01' -Severity 'High' -Category 'Security' -Title 'Firewall disabled on one or more profiles' -Description 'At least one firewall profile is disabled.' -Evidence $evidence -RecommendedActions @(
                'Re-enable firewall profiles unless policy explicitly disables them.'
                'Verify expected network profile assignment.'
            ) -ConfigChanges @(
                @{ Path = 'modules.securityScan.enabled'; Value = $true; Reason = 'Security baseline remediation' }
            ) -Citations @(
                @{ Tier = 'Microsoft Learn'; Source = 'Windows Defender Firewall overview'; Url = 'https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/' }
            )
        }
    }

    return @($findings)
}

function Invoke-AnalyzeSectionE {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Section)

    $findings = @()

    $dns = @(Get-CollectorData -Section $Section -Key 'DNS')
    $wsus = Get-CollectorData -Section $Section -Key 'WSUS'

    if (($wsus -is [hashtable]) -and $wsus.ContainsKey('IsWSUSManaged') -and $wsus.IsWSUSManaged) {
        $wsusServer = if ($wsus.ContainsKey('WSUSServer')) { $wsus.WSUSServer } else { 'Unknown' }
        $findings += New-Finding -Id 'E-WSUS-01' -Severity 'High' -Category 'WindowsUpdate' -Title 'WSUS-managed endpoint detected' -Description 'Update policy is likely controlled by WSUS. Aggressive local reset operations may conflict with policy.' -Evidence @("WSUSServer=$wsusServer") -RecommendedActions @(
            'Keep local reset-components disabled by default.'
            'Coordinate update remediation with WSUS administrators.'
        ) -ConfigChanges @(
            @{ Path = 'modules.windowsUpdate.resetComponents'; Value = $false; Reason = 'WSUS policy management' }
            @{ Path = 'modules.windowsUpdate.clearSoftwareDistribution'; Value = $false; Reason = 'WSUS policy management' }
        ) -Citations @(
            @{ Tier = 'Microsoft Learn'; Source = 'Manage updates with WSUS'; Url = 'https://learn.microsoft.com/windows-server/administration/windows-server-update-services/' }
        )
    }

    if ($dns.Count -gt 0) {
        $invalidDns = @(
            $dns | Where-Object {
                ($_ -is [hashtable]) -and
                $_.ContainsKey('Servers') -and
                ($_.Servers -is [array]) -and
                ($_.Servers.Count -eq 0)
            }
        )
        if ($invalidDns.Count -gt 0) {
            $evidence = $invalidDns | ForEach-Object {
                $alias = if ($_.ContainsKey('AdapterAlias')) { $_.AdapterAlias } else { 'UnknownAdapter' }
                "Adapter: $alias"
            }

            $findings += New-Finding -Id 'E-DNS-01' -Severity 'Medium' -Category 'Network' -Title 'Adapters without DNS servers detected' -Description 'One or more adapters have no configured DNS servers.' -Evidence @($evidence) -RecommendedActions @('Validate adapter DNS settings and DHCP health before update remediation.') -ConfigChanges @() -Citations @(
                @{ Tier = 'Microsoft Learn'; Source = 'TCP/IP and DNS troubleshooting'; Url = 'https://learn.microsoft.com/troubleshoot/windows-client/networking/' }
            )
        }
    }

    return @($findings)
}

function New-TailoredConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$BaseConfig,

        [Parameter(Mandatory = $true)]
        [hashtable[]]$Findings
    )

    $tailored = ConvertTo-Hashtable -InputObject $BaseConfig
    $changeLog = @()

    foreach ($finding in $Findings) {
        foreach ($change in @($finding.ConfigChanges)) {
            if (-not $change.ContainsKey('Path')) {
                continue
            }

            $path = [string]$change.Path
            $value = $change.Value
            $reason = if ($change.ContainsKey('Reason')) { [string]$change.Reason } else { $finding.Title }

            Set-NestedValue -Target $tailored -Path $path -Value $value
            $changeLog += [ordered]@{
                Path      = $path
                Value     = $value
                Reason    = $reason
                FindingId = $finding.Id
            }
        }
    }

    return [ordered]@{
        Config  = $tailored
        Changes = $changeLog
    }
}

function New-RemediationPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Metadata,

        [Parameter(Mandatory = $true)]
        [hashtable[]]$Findings,

        [Parameter(Mandatory = $true)]
        [hashtable[]]$ConfigChanges,

        [Parameter(Mandatory = $true)]
        [string]$TailoredConfigPath
    )

    $severityIcon = @{
        Critical = '[!]' 
        High     = '[H]'
        Medium   = '[M]'
        Low      = '[L]'
        Info     = '[i]'
    }

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('# WinCare Remediation Plan')
    $lines.Add('')
    $lines.Add("- Generated: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))")
    $lines.Add("- Computer: $($Metadata.ComputerName)")
    $lines.Add("- Intake Timestamp: $($Metadata.Timestamp)")
    $lines.Add(('- Tailored Config: `{0}`' -f $TailoredConfigPath))
    $lines.Add('')

    $lines.Add('## Findings Summary')
    $lines.Add('')

    $severityOrder = @('Critical', 'High', 'Medium', 'Low', 'Info')
    foreach ($sev in $severityOrder) {
        $count = @($Findings | Where-Object { $_.Severity -eq $sev }).Count
        $lines.Add(('- {0}: {1}' -f $sev, $count))
    }

    $lines.Add('')
    $lines.Add('## Recommended Execution Focus')
    $lines.Add('')

    $topFindings = @($Findings | Sort-Object @{ Expression = { Get-SeverityWeight -Severity $_.Severity }; Descending = $true }, Id)
    foreach ($finding in $topFindings) {
        $icon = $severityIcon[$finding.Severity]
        $lines.Add(('### {0} [{1}] {2} (`{3}`)' -f $icon, $finding.Severity, $finding.Title, $finding.Id))
        $lines.Add('')
        $lines.Add($finding.Description)
        $lines.Add('')

        if (@($finding.Evidence).Count -gt 0) {
            $lines.Add('**Evidence**')
            foreach ($item in $finding.Evidence) {
                $lines.Add("- $item")
            }
            $lines.Add('')
        }

        if (@($finding.RecommendedActions).Count -gt 0) {
            $lines.Add('**Recommended Actions**')
            foreach ($item in $finding.RecommendedActions) {
                $lines.Add("- $item")
            }
            $lines.Add('')
        }

        if (@($finding.ConfigChanges).Count -gt 0) {
            $lines.Add('**Config Impacts**')
            foreach ($change in $finding.ConfigChanges) {
                $valueText = if ($null -eq $change.Value) { 'null' } else { [string]$change.Value }
                $lines.Add(('- `{0}` = `{1}` ({2})' -f $change.Path, $valueText, $change.Reason))
            }
            $lines.Add('')
        }

        if (@($finding.Citations).Count -gt 0) {
            $lines.Add('**Citations**')
            foreach ($citation in $finding.Citations) {
                $tier = if ($citation.ContainsKey('Tier')) { $citation.Tier } else { 'Unverified' }
                $source = if ($citation.ContainsKey('Source')) { $citation.Source } else { 'Unverified Source' }
                $url = if ($citation.ContainsKey('Url')) { $citation.Url } else { '' }
                $lines.Add("- [$tier] $source - $url")
            }
            $lines.Add('')
        }
    }

    $lines.Add('## Tailored Config Change List')
    $lines.Add('')
    if ($ConfigChanges.Count -eq 0) {
        $lines.Add('- No config changes were required. Base config remains unchanged.')
    }
    else {
        foreach ($change in $ConfigChanges) {
            $valueText = if ($null -eq $change.Value) { 'null' } else { [string]$change.Value }
            $lines.Add(('- `{0}` = `{1}` (from {2}: {3})' -f $change.Path, $valueText, $change.FindingId, $change.Reason))
        }
    }

    $lines.Add('')
    $lines.Add('## Safety Notes')
    $lines.Add('')
    $lines.Add('- This plan is generated from intake telemetry and does not execute remediation.')
    $lines.Add('- Protected Windows components must remain excluded from any debloat/removal paths.')
    $lines.Add('- Confirm restore point and registry backups are enabled before running WinCare execution phase.')

    return ($lines -join [Environment]::NewLine)
}

function Invoke-IntakeAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Intake,

        [Parameter(Mandatory = $true)]
        [hashtable]$BaseConfig
    )

    $sectionA = Find-Section -Intake $Intake -Candidates @('SectionA_OS_Hardware', 'SectionA')
    $sectionB = Find-Section -Intake $Intake -Candidates @('SectionB_Health', 'SectionB')
    $sectionC = Find-Section -Intake $Intake -Candidates @('SectionC_Software', 'SectionC')
    $sectionD = Find-Section -Intake $Intake -Candidates @('SectionD_Security', 'SectionD')
    $sectionE = Find-Section -Intake $Intake -Candidates @('SectionE_Network', 'SectionE')

    if ($null -eq $sectionA -or $null -eq $sectionB -or $null -eq $sectionC -or $null -eq $sectionD -or $null -eq $sectionE) {
        throw 'Intake JSON is missing one or more required sections (A-E).'
    }

    $findings = @()
    $findings += @(Invoke-AnalyzeSectionA -Section (ConvertTo-Hashtable -InputObject $sectionA))
    $findings += @(Invoke-AnalyzeSectionB -Section (ConvertTo-Hashtable -InputObject $sectionB))
    $findings += @(Invoke-AnalyzeSectionC -Section (ConvertTo-Hashtable -InputObject $sectionC))
    $findings += @(Invoke-AnalyzeSectionD -Section (ConvertTo-Hashtable -InputObject $sectionD))
    $findings += @(Invoke-AnalyzeSectionE -Section (ConvertTo-Hashtable -InputObject $sectionE))

    $tailorResult = New-TailoredConfig -BaseConfig $BaseConfig -Findings $findings

    return [ordered]@{
        Findings   = @($findings)
        Config     = $tailorResult.Config
        ConfigDiff = $tailorResult.Changes
    }
}

try {
    if (-not (Test-Path $IntakePath)) {
        throw "Intake file not found: $IntakePath"
    }

    if (-not (Test-Path $BaseConfigPath)) {
        throw "Base config file not found: $BaseConfigPath"
    }

    $timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
    if ([string]::IsNullOrWhiteSpace($OutputConfigPath)) {
        $OutputConfigPath = Join-Path $PSScriptRoot ("Reports\\WinCare.config.tailored.$timestamp.json")
    }
    if ([string]::IsNullOrWhiteSpace($RemediationPlanPath)) {
        $RemediationPlanPath = Join-Path $PSScriptRoot ("Reports\\WinCare.remediation.$timestamp.md")
    }

    Write-AnalyzeLog "Loading intake from: $IntakePath"
    $intakeObj = ConvertFrom-Json -InputObject (Get-Content -Path $IntakePath -Raw -ErrorAction Stop) -ErrorAction Stop
    $intake = ConvertTo-Hashtable -InputObject $intakeObj

    if (-not $intake.ContainsKey('_metadata')) {
        throw "Intake file missing '_metadata'"
    }

    Write-AnalyzeLog "Loading base config from: $BaseConfigPath"
    $baseConfigObj = ConvertFrom-Json -InputObject (Get-Content -Path $BaseConfigPath -Raw -ErrorAction Stop) -ErrorAction Stop
    $baseConfig = ConvertTo-Hashtable -InputObject $baseConfigObj

    Write-AnalyzeLog 'Running section analysis (A-E)...'
    $analysis = Invoke-IntakeAnalysis -Intake $intake -BaseConfig $baseConfig

    $tailoredJson = $analysis.Config | ConvertTo-Json -Depth 20
    Save-Utf8BomFile -Path $OutputConfigPath -Content $tailoredJson

    $metadata = ConvertTo-Hashtable -InputObject $intake._metadata
    $plan = New-RemediationPlan -Metadata $metadata -Findings $analysis.Findings -ConfigChanges $analysis.ConfigDiff -TailoredConfigPath $OutputConfigPath
    Save-Utf8BomFile -Path $RemediationPlanPath -Content $plan

    $criticalCount = @($analysis.Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount = @($analysis.Findings | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumCount = @($analysis.Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lowCount = @($analysis.Findings | Where-Object { $_.Severity -eq 'Low' }).Count
    $infoCount = @($analysis.Findings | Where-Object { $_.Severity -eq 'Info' }).Count

    Write-AnalyzeLog "Analysis complete. Findings: Critical=$criticalCount, High=$highCount, Medium=$mediumCount, Low=$lowCount, Info=$infoCount"
    Write-AnalyzeLog "Tailored config written to: $OutputConfigPath"
    Write-AnalyzeLog "Remediation plan written to: $RemediationPlanPath"

    if ($PassThru) {
        [pscustomobject]@{
            FindingsCount = @($analysis.Findings).Count
            Findings      = $analysis.Findings
            ConfigPath    = $OutputConfigPath
            PlanPath      = $RemediationPlanPath
            ConfigChanges = $analysis.ConfigDiff
        }
    }
}
catch {
    Write-AnalyzeLog "Analysis failed: $($_.Exception.Message)" -Level ERROR
    throw
}
