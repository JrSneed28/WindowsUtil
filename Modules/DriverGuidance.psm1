Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$utilsPath = Join-Path $PSScriptRoot '..\WinCareUtils.psm1'
Import-Module $utilsPath -Force -ErrorAction Stop

function Invoke-DriverGuidance {
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
        $moduleCfg = $cfg.modules.driverGuidance
        $dryRun = [bool]$cfg.preferences.dryRun

        if (-not $moduleCfg.enabled) {
            return New-WinCareResult -ModuleName 'DriverGuidance' -Status 'Skipped' -StartTime $start -Details @('Module disabled by config.')
        }

        $missing = @()
        if ($moduleCfg.checkForMissing) {
            $attempted++
            try {
                $missing = @(Get-CimInstance Win32_PnPEntity -ErrorAction Stop | Where-Object { $_.ConfigManagerErrorCode -ne 0 })
                $details += "Potential missing/problem devices: $($missing.Count)"
                $completed++
            }
            catch {
                $failed++
                $errors += "Failed to query missing/problem devices: $($_.Exception.Message)"
            }
        }

        $outdated = @()
        if ($moduleCfg.checkForOutdated) {
            $attempted++
            try {
                $drivers = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop)
                $threshold = (Get-Date).AddYears(-5)
                $outdated = @(
                    $drivers | Where-Object {
                        $_.DriverDate -and ([datetime]$_.DriverDate -lt $threshold)
                    }
                )
                $details += "Potential outdated drivers (>5 years): $($outdated.Count)"
                $completed++
            }
            catch {
                $failed++
                $errors += "Failed to query signed drivers: $($_.Exception.Message)"
            }
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
        $reportPath = Join-Path $reportDir ("DriverGuidance.{0}.md" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

        $lines = @(
            '# WinCare Driver Guidance Report',
            '',
            "Generated: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))",
            '',
            '## Missing or Problem Devices',
            "Count: $($missing.Count)",
            ''
        )

        foreach ($item in $missing | Select-Object -First 20) {
            $lines += "- $($item.Name) (ErrorCode=$($item.ConfigManagerErrorCode))"
        }

        $lines += @(
            '',
            '## Potentially Outdated Drivers',
            "Count: $($outdated.Count)",
            ''
        )

        foreach ($drv in $outdated | Select-Object -First 30) {
            $lines += "- $($drv.DeviceName) | $($drv.DriverVersion) | $($drv.DriverDate)"
        }

        $lines += @(
            '',
            '## Recommended Sources',
            '- Prefer OEM or device-vendor support portals first.',
            '- Use Microsoft Update Catalog when OEM package is unavailable.',
            '- Avoid unofficial third-party driver download sites.',
            '- Microsoft Update Catalog: https://www.catalog.update.microsoft.com/',
            '- Windows driver docs: https://learn.microsoft.com/windows-hardware/drivers/',
            ''
        )

        Save-WinCareFile -Path $reportPath -Content ($lines -join [Environment]::NewLine)
        $details += "Driver guidance report written to $reportPath"
        $undoArtifacts += $reportPath

        if ($moduleCfg.autoInstall) {
            $attempted++
            if ($dryRun) {
                $details += 'DryRun: would trigger Windows Update scan for driver availability.'
                $completed++
            }
            else {
                try {
                    $uso = Join-Path $env:windir 'System32\UsoClient.exe'
                    if (Test-Path $uso) {
                        & $uso StartScan | Out-Null
                        $details += 'Triggered Windows Update scan for potential driver offers.'
                        $nextSteps += 'Review Optional Updates in Windows Update before installing driver updates.'
                        $completed++
                    }
                    else {
                        $failed++
                        $errors += 'UsoClient.exe not found; cannot trigger update scan automatically.'
                    }
                }
                catch {
                    $failed++
                    $errors += "Driver auto-install trigger failed: $($_.Exception.Message)"
                }
            }
        }

        $status = if ($dryRun) { 'DryRun' } elseif ($failed -eq 0) { 'Success' } elseif ($completed -gt 0) { 'PartialSuccess' } else { 'Failed' }
        return New-WinCareResult -ModuleName 'DriverGuidance' -Status $status -StartTime $start -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps $nextSteps -ActionsAttempted $attempted -ActionsCompleted $completed -ActionsFailed $failed
    }
    catch {
        $errors += $_.Exception.Message
        return New-WinCareResult -ModuleName 'DriverGuidance' -Status 'Failed' -StartTime $start -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps $nextSteps -ActionsAttempted $attempted -ActionsCompleted $completed -ActionsFailed ($failed + 1)
    }
}

Export-ModuleMember -Function Invoke-DriverGuidance
