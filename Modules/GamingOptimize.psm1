Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$utilsPath = Join-Path $PSScriptRoot '..\WinCareUtils.psm1'
Import-Module $utilsPath -Force -ErrorAction Stop

function Invoke-GamingOptimize {
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
        $rootDir = Join-Path $PSScriptRoot '..'
        $backupDir = if ($cfg.preferences.backupDirectory) {
            [string]$cfg.preferences.backupDirectory
        }
        else {
            Join-Path $rootDir 'Backups'
        }
        $moduleCfg = $cfg.modules.gamingOptimize
        $dryRun = [bool]$cfg.preferences.dryRun

        if (-not $moduleCfg.enabled) {
            return New-WinCareResult -ModuleName 'GamingOptimize' -Status 'Skipped' -StartTime $start -Details @('Module disabled by config.')
        }

        $isAdmin = Test-IsAdministrator

        if ($moduleCfg.enableGameMode) {
            $attempted++
            if ($dryRun) {
                $details += 'DryRun: would enable Game Mode registry values.'
                $completed++
            }
            else {
                try {
                    $gameBarKey = 'HKCU:\Software\Microsoft\GameBar'
                    if (-not (Test-Path $gameBarKey)) { New-Item -Path $gameBarKey -Force | Out-Null }
                    New-ItemProperty -Path $gameBarKey -Name 'AllowAutoGameMode' -Value 1 -PropertyType DWord -Force | Out-Null
                    New-ItemProperty -Path $gameBarKey -Name 'AutoGameModeEnabled' -Value 1 -PropertyType DWord -Force | Out-Null
                    $details += 'Enabled Game Mode preferences for current user.'
                    $completed++
                }
                catch {
                    $failed++
                    $errors += "Game Mode enable failed: $($_.Exception.Message)"
                }
            }
        }

        if ($moduleCfg.setHighPerformancePower) {
            $attempted++
            if ($dryRun) {
                $details += 'DryRun: would set High performance power scheme if available.'
                $completed++
            }
            else {
                try {
                    $list = (& powercfg /L 2>&1 | Out-String)
                    $match = [regex]::Match($list, '([A-Fa-f0-9\-]{36}).*High performance')
                    if ($match.Success) {
                        $guid = $match.Groups[1].Value
                        & powercfg /SETACTIVE $guid | Out-Null
                        $details += "Set active power scheme to High performance ($guid)."
                        $nextSteps += 'If this is a laptop, review battery impact and switch plans when unplugged.'
                        $completed++
                    }
                    else {
                        $failed++
                        $errors += 'High performance power scheme not found.'
                    }
                }
                catch {
                    $failed++
                    $errors += "Power scheme update failed: $($_.Exception.Message)"
                }
            }
        }

        if ($moduleCfg.enableHAGS) {
            $attempted++
            if (-not $isAdmin) {
                $failed++
                $errors += 'HAGS toggle requires administrator privileges.'
            }
            elseif ($dryRun) {
                $details += 'DryRun: would set HwSchMode=2 for HAGS.'
                $completed++
            }
            else {
                try {
                    $graphicsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'
                    $backup = Export-RegistryBackup -KeyPath 'HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' -OutputPath (Join-Path $backupDir ("GraphicsDrivers.{0}.reg" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))) -Description 'Before enabling HAGS'
                    if ($null -ne $backup) { $undoArtifacts += [string]$backup }
                    New-ItemProperty -Path $graphicsKey -Name 'HwSchMode' -Value 2 -PropertyType DWord -Force | Out-Null
                    $details += 'Set HwSchMode=2 (requires reboot to fully apply).'
                    $nextSteps += 'Reboot to apply HAGS change.'
                    $completed++
                }
                catch {
                    $failed++
                    $errors += "HAGS configuration failed: $($_.Exception.Message)"
                }
            }
        }

        if ($moduleCfg.disableStartupItems) {
            $attempted++
            try {
                $startupItems = @(Get-CimInstance Win32_StartupCommand -ErrorAction Stop)
                $details += "Startup review only: found $($startupItems.Count) startup entries."
                $nextSteps += 'Review startup entries manually and disable only non-essential items.'
                $completed++
            }
            catch {
                $failed++
                $errors += "Startup inventory failed: $($_.Exception.Message)"
            }
        }

        if ($moduleCfg.optimizeNetworkSettings) {
            $attempted++
            if ($dryRun) {
                $details += 'DryRun: would flush DNS cache and collect TCP global settings.'
                $completed++
            }
            else {
                try {
                    & ipconfig /flushdns | Out-Null
                    $tcpInfo = (& netsh int tcp show global 2>&1 | Out-String)
                    $details += 'Flushed DNS cache and captured TCP global settings.'
                    $nextSteps += 'Review TCP settings output in console if network issues persist.'
                    if (-not [string]::IsNullOrWhiteSpace($tcpInfo)) {
                        Write-WinCareLog -Message $tcpInfo -Severity Debug
                    }
                    $completed++
                }
                catch {
                    $failed++
                    $errors += "Network optimization step failed: $($_.Exception.Message)"
                }
            }
        }

        if ($moduleCfg.applyRegistryTweaks) {
            $attempted++
            if ($dryRun) {
                $details += 'DryRun: would apply GameDVR-related registry tweaks.'
                $completed++
            }
            else {
                try {
                    if (-not (Test-Path $backupDir)) { New-Item -Path $backupDir -ItemType Directory -Force | Out-Null }
                    $backup1 = Export-RegistryBackup -KeyPath 'HKCU\System\GameConfigStore' -OutputPath (Join-Path $backupDir ("GameConfigStore.{0}.reg" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))) -Description 'Before GameDVR tweaks'
                    if ($null -ne $backup1) { $undoArtifacts += [string]$backup1 }

                    $key1 = 'HKCU:\System\GameConfigStore'
                    if (-not (Test-Path $key1)) { New-Item -Path $key1 -Force | Out-Null }
                    New-ItemProperty -Path $key1 -Name 'GameDVR_Enabled' -Value 0 -PropertyType DWord -Force | Out-Null

                    $key2 = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR'
                    if (-not (Test-Path $key2)) { New-Item -Path $key2 -Force | Out-Null }
                    New-ItemProperty -Path $key2 -Name 'AppCaptureEnabled' -Value 0 -PropertyType DWord -Force | Out-Null

                    $details += 'Applied GameDVR capture-disable tweaks for current user.'
                    $completed++
                }
                catch {
                    $failed++
                    $errors += "Registry tweak step failed: $($_.Exception.Message)"
                }
            }
        }

        $status = if ($dryRun) { 'DryRun' } elseif ($failed -eq 0) { 'Success' } elseif ($completed -gt 0) { 'PartialSuccess' } else { 'Failed' }
        return New-WinCareResult -ModuleName 'GamingOptimize' -Status $status -StartTime $start -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps $nextSteps -ActionsAttempted $attempted -ActionsCompleted $completed -ActionsFailed $failed
    }
    catch {
        $errors += $_.Exception.Message
        return New-WinCareResult -ModuleName 'GamingOptimize' -Status 'Failed' -StartTime $start -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps $nextSteps -ActionsAttempted $attempted -ActionsCompleted $completed -ActionsFailed ($failed + 1)
    }
}

Export-ModuleMember -Function Invoke-GamingOptimize
