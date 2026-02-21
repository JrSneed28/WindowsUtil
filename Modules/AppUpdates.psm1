Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$utilsPath = Join-Path $PSScriptRoot '..\WinCareUtils.psm1'
Import-Module $utilsPath -Force -ErrorAction Stop

function Invoke-AppUpdates {
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
        $moduleCfg = $cfg.modules.appUpdates
        $dryRun = [bool]$cfg.preferences.dryRun

        if (-not $moduleCfg.enabled) {
            return New-WinCareResult -ModuleName 'AppUpdates' -Status 'Skipped' -StartTime $start -Details @('Module disabled by config.')
        }

        if (-not $moduleCfg.useWinGet) {
            return New-WinCareResult -ModuleName 'AppUpdates' -Status 'Skipped' -StartTime $start -Details @('WinGet usage disabled by config.')
        }

        $winget = Get-Command winget -ErrorAction SilentlyContinue
        if ($null -eq $winget) {
            return New-WinCareResult -ModuleName 'AppUpdates' -Status 'Skipped' -StartTime $start -Details @('winget executable not found.') -NextSteps @('Install App Installer from Microsoft Store to enable WinGet-based updates.')
        }

        $rootDir = Join-Path $PSScriptRoot '..'
        $reportsDir = if ($cfg.preferences.reportDirectory) {
            [string]$cfg.preferences.reportDirectory
        }
        else {
            Join-Path $rootDir 'Reports'
        }
        if (-not (Test-Path $reportsDir)) {
            New-Item -Path $reportsDir -ItemType Directory -Force | Out-Null
        }

        $attempted++
        $backupPath = Join-Path $reportsDir ("winget-export-{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
        if ($dryRun) {
            $details += "DryRun: would run winget export to $backupPath"
            $completed++
        }
        else {
            & winget export -o $backupPath --include-versions --accept-source-agreements | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "winget export failed with exit code $LASTEXITCODE"
            }
            $undoArtifacts += $backupPath
            $details += "Exported installed app manifest to $backupPath"
            $completed++
        }

        if ($moduleCfg.upgradeAll) {
            $attempted++
            if ($dryRun) {
                $details += 'DryRun: would run winget upgrade --all'
                $completed++
            }
            else {
                try {
                    & winget upgrade --all --accept-package-agreements --accept-source-agreements | Out-Null
                    if ($LASTEXITCODE -ne 0) {
                        throw "winget upgrade --all failed with exit code $LASTEXITCODE"
                    }
                    $details += 'Executed winget upgrade --all.'
                    $completed++
                }
                catch {
                    $failed++
                    $errors += "winget upgrade --all failed: $($_.Exception.Message)"
                }
            }
        }
        else {
            $approved = @($moduleCfg.approvedPackages)
            if ($approved.Count -eq 0) {
                $details += 'No approved packages defined; no package upgrades executed.'
            }
            else {
                foreach ($pkgId in $approved) {
                    $attempted++
                    if ($dryRun) {
                        $details += "DryRun: would upgrade package id '$pkgId'"
                        $completed++
                    }
                    else {
                        try {
                            & winget upgrade --id $pkgId --accept-package-agreements --accept-source-agreements | Out-Null
                            if ($LASTEXITCODE -ne 0) {
                                throw "winget upgrade --id $pkgId failed with exit code $LASTEXITCODE"
                            }
                            $details += "Upgraded package id '$pkgId'."
                            $completed++
                        }
                        catch {
                            $failed++
                            $errors += "Failed to upgrade '$pkgId': $($_.Exception.Message)"
                        }
                    }
                }
            }
        }

        $status = if ($dryRun) { 'DryRun' } elseif ($failed -eq 0) { 'Success' } elseif ($completed -gt 0) { 'PartialSuccess' } else { 'Failed' }
        return New-WinCareResult -ModuleName 'AppUpdates' -Status $status -StartTime $start -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps $nextSteps -ActionsAttempted $attempted -ActionsCompleted $completed -ActionsFailed $failed
    }
    catch {
        $errors += $_.Exception.Message
        return New-WinCareResult -ModuleName 'AppUpdates' -Status 'Failed' -StartTime $start -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps $nextSteps -ActionsAttempted $attempted -ActionsCompleted $completed -ActionsFailed ($failed + 1)
    }
}

Export-ModuleMember -Function Invoke-AppUpdates
