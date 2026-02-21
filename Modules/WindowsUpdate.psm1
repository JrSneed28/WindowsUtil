Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$utilsPath = Join-Path $PSScriptRoot '..\WinCareUtils.psm1'
Import-Module $utilsPath -Force -ErrorAction Stop

function Invoke-WindowsUpdateFix {
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
        $moduleCfg = $cfg.modules.windowsUpdate
        $dryRun = [bool]$cfg.preferences.dryRun

        if (-not $moduleCfg.enabled) {
            Write-WinCareLog -Message 'WindowsUpdate module disabled by config.' -Severity Info
            return New-WinCareResult -ModuleName 'WindowsUpdate' -Status 'Skipped' -StartTime $start -Details @('Module disabled by config.')
        }

        if ($moduleCfg.diagnosePending) {
            $attempted++
            $pending = Test-PendingReboot
            $details += "Pending reboot: $($pending.Pending)"
            if ($pending.Pending) {
                $nextSteps += 'Reboot system before aggressive update remediation.'
                $details += "Pending reasons: $($pending.Reasons -join ', ')"
            }
            $completed++
        }

        if ($moduleCfg.resetComponents) {
            $attempted++
            if ($dryRun) {
                $details += 'DryRun: Windows Update component reset skipped.'
                $completed++
            }
            else {
                if (-not (Test-IsAdministrator)) {
                    $failed++
                    $errors += 'Windows Update component reset requires administrator privileges.'
                    $nextSteps += 'Re-run elevated before using resetComponents.'
                }

                $serviceOrder = @('BITS', 'wuauserv', 'appidsvc', 'cryptsvc')
                if ($failed -eq 0) {
                    $stopped = @()

                    try {
                        foreach ($svc in $serviceOrder) {
                            $service = Get-Service -Name $svc -ErrorAction Stop
                            if ($service.Status -ne 'Stopped') {
                                Stop-Service -Name $svc -Force -ErrorAction Stop
                                $stopped += $svc
                            }
                        }

                        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                        $winDir = $env:windir
                        $sd = Join-Path $winDir 'SoftwareDistribution'
                        $catroot = Join-Path $winDir 'System32\catroot2'

                        if ($moduleCfg.clearSoftwareDistribution -and (Test-Path $sd)) {
                            $sdBackup = "${sd}.WinCare.$stamp"
                            if ($PSCmdlet.ShouldProcess($sd, "Rename to $sdBackup")) {
                                Rename-Item -Path $sd -NewName (Split-Path $sdBackup -Leaf) -ErrorAction Stop
                                $undoArtifacts += $sdBackup
                                $details += "Renamed SoftwareDistribution to $sdBackup"
                            }
                        }

                        if ($moduleCfg.clearSoftwareDistribution -and (Test-Path $catroot)) {
                            $catBackup = "${catroot}.WinCare.$stamp"
                            if ($PSCmdlet.ShouldProcess($catroot, "Rename to $catBackup")) {
                                Rename-Item -Path $catroot -NewName (Split-Path $catBackup -Leaf) -ErrorAction Stop
                                $undoArtifacts += $catBackup
                                $details += "Renamed catroot2 to $catBackup"
                            }
                        }

                        $details += 'Windows Update component reset sequence completed.'
                        $completed++
                    }
                    catch {
                        $failed++
                        $errors += "Windows Update resetComponents failed: $($_.Exception.Message)"
                        $nextSteps += 'Reset failed partway through. Validate service states and rerun elevated if needed.'
                    }
                    finally {
                        foreach ($svc in @('cryptsvc', 'appidsvc', 'wuauserv', 'BITS')) {
                            try {
                                Start-Service -Name $svc -ErrorAction Stop
                            }
                            catch {
                                $failed++
                                $errors += "Unable to restart service ${svc}: $($_.Exception.Message)"
                            }
                        }
                    }
                }
            }
        }

        $status = if ($dryRun) { 'DryRun' } elseif ($failed -eq 0) { 'Success' } elseif ($completed -gt 0) { 'PartialSuccess' } else { 'Failed' }
        return New-WinCareResult -ModuleName 'WindowsUpdate' -Status $status -StartTime $start -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps $nextSteps -ActionsAttempted $attempted -ActionsCompleted $completed -ActionsFailed $failed
    }
    catch {
        $errors += $_.Exception.Message
        return New-WinCareResult -ModuleName 'WindowsUpdate' -Status 'Failed' -StartTime $start -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps $nextSteps -ActionsAttempted $attempted -ActionsCompleted $completed -ActionsFailed ($failed + 1)
    }
}

Export-ModuleMember -Function Invoke-WindowsUpdateFix
