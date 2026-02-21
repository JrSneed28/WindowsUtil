Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$utilsPath = Join-Path $PSScriptRoot '..\WinCareUtils.psm1'
Import-Module $utilsPath -Force -ErrorAction Stop

function Test-WinCarePackageExcluded {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PackageName,

        [Parameter(Mandatory = $true)]
        [string[]]$Patterns
    )

    foreach ($pattern in $Patterns) {
        if ($PackageName -like $pattern) {
            return $true
        }
    }

    return $false
}

function Invoke-Debloat {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter()]
        [string]$ConfigPath = (Join-Path $PSScriptRoot '..\WinCare.config.json')
    )

    $start = Get-Date
    $details = @()
    $errors = @()
    $nextSteps = @()
    $undoArtifacts = @()
    $attempted = 0
    $completed = 0
    $failed = 0
    $dryRun = $false

    try {
        $cfg = Get-WinCareConfig -Path $ConfigPath
        $moduleCfg = $cfg.modules.debloat
        $dryRun = [bool]$cfg.preferences.dryRun

        if (-not $moduleCfg.enabled) {
            return New-WinCareResult -ModuleName 'Debloat' -Status 'Skipped' -StartTime $start -Details @('Module disabled by config.')
        }

        if ($moduleCfg.mode -ne 'allowlist') {
            return New-WinCareResult -ModuleName 'Debloat' -Status 'Skipped' -StartTime $start -Details @("Unsupported mode '$($moduleCfg.mode)'; only allowlist mode is permitted.")
        }

        $requiredExclusions = @(
            'Microsoft.WindowsStore',
            'Microsoft.WindowsCalculator',
            'Microsoft.WindowsTerminal',
            'Microsoft.DesktopAppInstaller',
            'Microsoft.SecHealthUI',
            'Microsoft.WindowsSecurity',
            'Microsoft.UI.Xaml.*',
            'Microsoft.VCLibs.*',
            'Microsoft.NET.*'
        )
        $exclusions = @($requiredExclusions + $cfg.debloat.hardcodedExclusions + $cfg.debloat.additionalExclusions | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)

        $categoryToTargetKey = @{
            system            = 'system'
            games             = 'entertainment'
            social            = 'social'
            ads               = 'ads'
            microsoftConsumer = 'microsoftConsumer'
        }

        $targets = @()
        foreach ($catProp in $moduleCfg.categories.PSObject.Properties) {
            if ($catProp.Value -ne $true) {
                continue
            }

            if (-not $categoryToTargetKey.ContainsKey($catProp.Name)) {
                continue
            }

            $targetKey = $categoryToTargetKey[$catProp.Name]
            if ($cfg.debloat.removalTargets.PSObject.Properties.Name -contains $targetKey) {
                $targets += @($cfg.debloat.removalTargets.$targetKey)
            }
        }

        $targets = @($targets | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)

        if ($targets.Count -eq 0) {
            return New-WinCareResult -ModuleName 'Debloat' -Status 'Skipped' -StartTime $start -Details @('No enabled debloat categories produced any removal targets.')
        }

        $rootDir = Join-Path $PSScriptRoot '..'
        $reportDir = if ($cfg.preferences.reportDirectory) {
            [string]$cfg.preferences.reportDirectory
        }
        else {
            Join-Path $rootDir 'Reports'
        }
        if (-not (Test-Path $reportDir)) {
            New-Item -Path $reportDir -ItemType Directory -Force | Out-Null
        }

        $manifestPath = Join-Path $reportDir ("Debloat.Manifest.{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        $removed = @()
        $skipped = @()

        foreach ($target in $targets) {
            $attempted++

            if (Test-WinCarePackageExcluded -PackageName $target -Patterns $exclusions) {
                $skipped += "Excluded target skipped: $target"
                $details += "Excluded target skipped: $target"
                $completed++
                continue
            }

            $matches = @()
            try {
                $matches = @(Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $target })
            }
            catch {
                $failed++
                $errors += "Failed to enumerate Appx packages for target '$target': $($_.Exception.Message)"
                continue
            }

            if ($matches.Count -eq 0) {
                $details += "No package matches for target '$target'."
                $completed++
                continue
            }

            foreach ($pkg in $matches) {
                if (Test-WinCarePackageExcluded -PackageName $pkg.Name -Patterns $exclusions) {
                    $skipped += "Excluded package skipped: $($pkg.Name)"
                    continue
                }

                if ($dryRun) {
                    $details += "DryRun: would remove package $($pkg.PackageFullName)"
                    $removed += [ordered]@{ Name = $pkg.Name; FullName = $pkg.PackageFullName; Removed = $false; DryRun = $true }
                    continue
                }

                if ($PSCmdlet.ShouldProcess($pkg.PackageFullName, 'Remove Appx package')) {
                    try {
                        Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                        $details += "Removed package: $($pkg.PackageFullName)"
                        $removed += [ordered]@{ Name = $pkg.Name; FullName = $pkg.PackageFullName; Removed = $true; DryRun = $false }
                    }
                    catch {
                        $failed++
                        $errors += "Failed to remove $($pkg.PackageFullName): $($_.Exception.Message)"
                    }
                }
            }

            if ($moduleCfg.removeProvisionedPackages -and -not $dryRun) {
                try {
                    $provisioned = @(Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $target })
                    foreach ($prov in $provisioned) {
                        if (-not (Test-WinCarePackageExcluded -PackageName $prov.DisplayName -Patterns $exclusions)) {
                            Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop | Out-Null
                            $details += "Removed provisioned package: $($prov.PackageName)"
                        }
                    }
                }
                catch {
                    $failed++
                    $errors += "Provisioned package cleanup failed for target '$target': $($_.Exception.Message)"
                }
            }

            $completed++
        }

        $manifest = [ordered]@{
            GeneratedAt = (Get-Date).ToString('o')
            Removed     = $removed
            Skipped     = $skipped
            Errors      = $errors
            Targets     = $targets
            Exclusions  = $exclusions
        }

        Save-WinCareFile -Path $manifestPath -Content ($manifest | ConvertTo-Json -Depth 8)
        $undoArtifacts += $manifestPath
        $nextSteps += 'Use Debloat manifest to reinstall packages from Microsoft Store or winget where available.'

        $status = if ($dryRun) { 'DryRun' } elseif ($failed -eq 0) { 'Success' } elseif ($completed -gt 0) { 'PartialSuccess' } else { 'Failed' }
        return New-WinCareResult -ModuleName 'Debloat' -Status $status -StartTime $start -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps $nextSteps -ActionsAttempted $attempted -ActionsCompleted $completed -ActionsFailed $failed
    }
    catch {
        $errors += $_.Exception.Message
        return New-WinCareResult -ModuleName 'Debloat' -Status 'Failed' -StartTime $start -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps $nextSteps -ActionsAttempted $attempted -ActionsCompleted $completed -ActionsFailed ($failed + 1)
    }
}

Export-ModuleMember -Function Invoke-Debloat
