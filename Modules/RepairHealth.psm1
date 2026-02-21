Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$utilsPath = Join-Path $PSScriptRoot '..\WinCareUtils.psm1'
Import-Module $utilsPath -Force -ErrorAction Stop

function Invoke-RepairHealth {
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
        $moduleCfg = $cfg.modules.repairHealth
        $dryRun = [bool]$cfg.preferences.dryRun

        if (-not $moduleCfg.enabled) {
            Write-WinCareLog -Message 'RepairHealth module disabled by config.' -Severity Info
            return New-WinCareResult -ModuleName 'RepairHealth' -Status 'Skipped' -StartTime $start -Details @('Module disabled by config.')
        }

        Write-WinCareLog -Message 'Starting RepairHealth module.' -Severity Info

        $attempted++
        $checkOutput = ''
        if ($dryRun) {
            $details += 'DryRun: DISM CheckHealth skipped.'
            Write-WinCareLog -Message 'DryRun active: would run DISM /Online /Cleanup-Image /CheckHealth.' -Severity Info
            $completed++
        }
        else {
            $checkOutput = Invoke-WithRetry -OperationName 'DISM CheckHealth' -MaxRetries 1 -BaseDelaySeconds 2 -ScriptBlock {
                (& dism.exe /Online /Cleanup-Image /CheckHealth 2>&1 | Out-String)
            }
            $completed++
            $details += 'DISM CheckHealth executed.'
        }

        $needsRepair = ($checkOutput -match 'repairable' -or $checkOutput -match 'component store corruption')

        if ($moduleCfg.runDISMScanHealth) {
            $attempted++
            if ($dryRun) {
                $details += 'DryRun: DISM ScanHealth skipped.'
                Write-WinCareLog -Message 'DryRun active: would run DISM /Online /Cleanup-Image /ScanHealth.' -Severity Info
                $completed++
            }
            else {
                $scanOutput = Invoke-WithRetry -OperationName 'DISM ScanHealth' -MaxRetries 1 -BaseDelaySeconds 2 -ScriptBlock {
                    (& dism.exe /Online /Cleanup-Image /ScanHealth 2>&1 | Out-String)
                }
                if ($scanOutput -match 'repairable') {
                    $needsRepair = $true
                }
                $details += 'DISM ScanHealth executed.'
                $completed++
            }
        }

        if ($moduleCfg.runDISMRestoreHealth) {
            $attempted++
            if ($dryRun) {
                $details += 'DryRun: DISM RestoreHealth skipped.'
                Write-WinCareLog -Message 'DryRun active: would run DISM /Online /Cleanup-Image /RestoreHealth.' -Severity Info
                $completed++
            }
            elseif ($needsRepair) {
                try {
                    $restoreOutput = Invoke-WithRetry -OperationName 'DISM RestoreHealth' -MaxRetries 1 -BaseDelaySeconds 3 -ScriptBlock {
                        (& dism.exe /Online /Cleanup-Image /RestoreHealth 2>&1 | Out-String)
                    }
                    $details += 'DISM RestoreHealth executed.'
                    if ($restoreOutput -match '0x800f081f|0x800f0906|0x800f0907') {
                        $nextSteps += 'DISM source-related failure detected (0x800f081f/906/907). Provide a valid repair source (install media or WSUS policy review).'
                    }
                    $completed++
                }
                catch {
                    $failed++
                    $errors += "DISM RestoreHealth failed: $($_.Exception.Message)"
                }
            }
            else {
                $details += 'DISM RestoreHealth skipped because no repair signal was detected.'
                $completed++
            }
        }

        if ($moduleCfg.runSFC) {
            $attempted++
            if ($dryRun) {
                $details += 'DryRun: SFC /SCANNOW skipped.'
                Write-WinCareLog -Message 'DryRun active: would run SFC /SCANNOW.' -Severity Info
                $completed++
            }
            else {
                try {
                    $sfcOutput = Invoke-WithRetry -OperationName 'SFC Scan' -MaxRetries 1 -BaseDelaySeconds 2 -ScriptBlock {
                        (& sfc.exe /SCANNOW 2>&1 | Out-String)
                    }
                    if ($sfcOutput -match 'could not perform|could not start') {
                        $errors += 'SFC reported execution failure.'
                        $failed++
                    }
                    elseif ($sfcOutput -match 'could not repair') {
                        $details += 'SFC found corruption it could not repair.'
                        $nextSteps += 'Review CBS.log and consider offline servicing source.'
                        $completed++
                    }
                    else {
                        $details += 'SFC completed.'
                        $completed++
                    }
                }
                catch {
                    $failed++
                    $errors += "SFC failed: $($_.Exception.Message)"
                }
            }
        }

        if ($moduleCfg.runCheckDisk) {
            $attempted++
            $drive = if ([string]::IsNullOrWhiteSpace($moduleCfg.checkDiskDrive)) { 'C:' } else { [string]$moduleCfg.checkDiskDrive }
            if ($dryRun) {
                $details += "DryRun: chkdsk $drive /scan skipped."
                $completed++
            }
            else {
                try {
                    $null = & chkdsk.exe $drive /scan 2>&1 | Out-String
                    $details += "CHKDSK scan executed for $drive (/scan only)."
                    $nextSteps += 'No /f or /r was executed in-session; schedule offline repairs manually if required.'
                    $completed++
                }
                catch {
                    $failed++
                    $errors += "CHKDSK scan failed for ${drive}: $($_.Exception.Message)"
                }
            }
        }

        $status = if ($dryRun) { 'DryRun' } elseif ($failed -eq 0) { 'Success' } elseif ($completed -gt 0) { 'PartialSuccess' } else { 'Failed' }
        return New-WinCareResult -ModuleName 'RepairHealth' -Status $status -StartTime $start -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps $nextSteps -ActionsAttempted $attempted -ActionsCompleted $completed -ActionsFailed $failed
    }
    catch {
        $errors += $_.Exception.Message
        return New-WinCareResult -ModuleName 'RepairHealth' -Status 'Failed' -StartTime $start -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps $nextSteps -ActionsAttempted $attempted -ActionsCompleted $completed -ActionsFailed ($failed + 1)
    }
}

Export-ModuleMember -Function Invoke-RepairHealth
