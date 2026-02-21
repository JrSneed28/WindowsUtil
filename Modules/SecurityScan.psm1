Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$utilsPath = Join-Path $PSScriptRoot '..\WinCareUtils.psm1'
Import-Module $utilsPath -Force -ErrorAction Stop

function Invoke-SecurityScan {
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
        $moduleCfg = $cfg.modules.securityScan
        $dryRun = [bool]$cfg.preferences.dryRun

        if (-not $moduleCfg.enabled) {
            return New-WinCareResult -ModuleName 'SecurityScan' -Status 'Skipped' -StartTime $start -Details @('Module disabled by config.')
        }

        $mpAvailable = $null -ne (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)
        if (-not $mpAvailable) {
            $errors += 'Defender PowerShell cmdlets are unavailable on this system.'
            return New-WinCareResult -ModuleName 'SecurityScan' -Status 'Failed' -StartTime $start -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps @('Install or enable Defender management cmdlets and retry.') -ActionsAttempted 1 -ActionsCompleted 0 -ActionsFailed 1
        }

        $attempted++
        $avProducts = @()
        try {
            $avProducts = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop)
        }
        catch {
            $details += 'Could not query SecurityCenter2 AntiVirusProduct; proceeding with Defender status only.'
        }

        $thirdParty = @(
            $avProducts | Where-Object {
                $_.displayName -and $_.displayName -notmatch 'Windows Defender|Microsoft Defender'
            }
        )
        $hasThirdParty = $thirdParty.Count -gt 0
        if ($hasThirdParty) {
            $details += "Third-party AV detected: $($thirdParty.displayName -join ', ')"
            $nextSteps += 'Defender scan actions were skipped to avoid duplicate scanning with non-Defender AV.'
        }
        $completed++

        if ($moduleCfg.checkDefenderStatus) {
            $attempted++
            $status = Get-MpComputerStatus
            $details += "Defender RTP: $($status.RealTimeProtectionEnabled); SignatureAgeDays: $($status.AntivirusSignatureAge)"
            if (-not $status.RealTimeProtectionEnabled) {
                $nextSteps += 'Real-time protection appears disabled. Re-enable Defender protections per policy.'
            }
            $completed++
        }

        if (-not $hasThirdParty -and $moduleCfg.updateDefinitions) {
            $attempted++
            if ($dryRun) {
                $details += 'DryRun: Update-MpSignature skipped.'
                $completed++
            }
            else {
                try {
                    Update-MpSignature -ErrorAction Stop | Out-Null
                    $details += 'Defender signatures updated.'
                    $completed++
                }
                catch {
                    $failed++
                    $errors += "Update-MpSignature failed: $($_.Exception.Message)"
                }
            }
        }

        if (-not $hasThirdParty -and $moduleCfg.runQuickScan) {
            $attempted++
            if ($dryRun) {
                $details += 'DryRun: Defender QuickScan skipped.'
                $completed++
            }
            else {
                try {
                    Start-MpScan -ScanType QuickScan -ErrorAction Stop
                    $details += 'Defender quick scan started.'
                    $completed++
                }
                catch {
                    $failed++
                    $errors += "Quick scan failed: $($_.Exception.Message)"
                }
            }
        }

        if (-not $hasThirdParty -and $moduleCfg.runFullScan) {
            $attempted++
            if ($dryRun) {
                $details += 'DryRun: Defender FullScan skipped.'
                $completed++
            }
            else {
                try {
                    Start-MpScan -ScanType FullScan -ErrorAction Stop
                    $details += 'Defender full scan started.'
                    $completed++
                }
                catch {
                    $failed++
                    $errors += "Full scan failed: $($_.Exception.Message)"
                }
            }
        }

        $status = if ($dryRun) { 'DryRun' } elseif ($failed -eq 0) { 'Success' } elseif ($completed -gt 0) { 'PartialSuccess' } else { 'Failed' }
        return New-WinCareResult -ModuleName 'SecurityScan' -Status $status -StartTime $start -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps $nextSteps -ActionsAttempted $attempted -ActionsCompleted $completed -ActionsFailed $failed
    }
    catch {
        $errors += $_.Exception.Message
        return New-WinCareResult -ModuleName 'SecurityScan' -Status 'Failed' -StartTime $start -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps $nextSteps -ActionsAttempted $attempted -ActionsCompleted $completed -ActionsFailed ($failed + 1)
    }
}

Export-ModuleMember -Function Invoke-SecurityScan
