#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'WinCare.config.json'),

    [Parameter()]
    [switch]$DryRun,

    [Parameter()]
    [switch]$AuditOnly,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [string[]]$ModulesOnly = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$utilsPath = Join-Path $PSScriptRoot 'WinCareUtils.psm1'
Import-Module $utilsPath -Force -ErrorAction Stop

function New-PreFlightModuleResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$PreFlightResult,

        [Parameter(Mandatory = $true)]
        [datetime]$StartTime
    )

    $details = @()
    $errors = @()
    $nextSteps = @()
    $undoArtifacts = @()

    foreach ($check in @($PreFlightResult.Checks)) {
        $details += "$($check.Name): $($check.Status) - $($check.Message)"
    }

    if ($PreFlightResult.RestorePoint -and $PreFlightResult.RestorePoint.Message) {
        $details += "RestorePoint: $($PreFlightResult.RestorePoint.Status) - $($PreFlightResult.RestorePoint.Message)"
    }

    if ($PreFlightResult.RegistryBackup -and @($PreFlightResult.RegistryBackup.BackupFiles).Count -gt 0) {
        $undoArtifacts += @($PreFlightResult.RegistryBackup.BackupFiles)
    }

    if (-not $PreFlightResult.CanProceed) {
        $errors += @($PreFlightResult.BlockReasons)
        $nextSteps += 'Resolve pre-flight block reasons and rerun without -Force.'
    }

    $status = if ($PreFlightResult.CanProceed) { 'Success' } else { 'Failed' }
    $attempted = @($PreFlightResult.Checks).Count
    $failed = @($PreFlightResult.Checks | Where-Object { $_.Status -eq 'Fail' }).Count
    $completed = [math]::Max(0, $attempted - $failed)

    return New-WinCareResult -ModuleName 'PreFlight' -Status $status -StartTime $StartTime -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps $nextSteps -ActionsAttempted $attempted -ActionsCompleted $completed -ActionsFailed $failed
}

try {
    $bannerTime = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $mode = if ($AuditOnly) { 'AUDIT-ONLY' } elseif ($DryRun) { 'DRY-RUN' } else { 'EXECUTION' }
    Write-Output "=== WinCare v1.0.0 | Mode: $mode | $bannerTime ==="

    $cfg = Get-WinCareConfig -Path $ConfigPath

    $logDir = if ($cfg.preferences.logDirectory) { [string]$cfg.preferences.logDirectory } else { Join-Path $PSScriptRoot 'Logs' }
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    $runStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $logFile = Join-Path $logDir ("WinCare.$runStamp.log")
    Set-WinCareLogFile -Path $logFile
    Write-WinCareLog -Message "WinCare starting. ConfigPath=$ConfigPath" -Severity Info

    if ($DryRun) {
        $cfg.preferences.dryRun = $true
        Write-WinCareLog -Message 'DryRun switch enabled. WhatIf preference is active.' -Severity Warning
    }

    if (-not (Test-IsAdministrator)) {
        Write-WinCareLog -Message 'Running without elevation. Some module operations may fail or be skipped.' -Severity Warning
    }

    $effectiveConfigPath = $ConfigPath
    if ($DryRun) {
        $tempPath = Join-Path $env:TEMP ("WinCare.config.runtime.$runStamp.json")
        Save-WinCareFile -Path $tempPath -Content ($cfg | ConvertTo-Json -Depth 20)
        $effectiveConfigPath = $tempPath
        $WhatIfPreference = $true
    }

    $moduleFiles = [ordered]@{
        PreFlight      = 'Modules\PreFlight.psm1'
        RepairHealth   = 'Modules\RepairHealth.psm1'
        WindowsUpdate  = 'Modules\WindowsUpdate.psm1'
        SecurityScan   = 'Modules\SecurityScan.psm1'
        Debloat        = 'Modules\Debloat.psm1'
        AppUpdates     = 'Modules\AppUpdates.psm1'
        DriverGuidance = 'Modules\DriverGuidance.psm1'
        GamingOptimize = 'Modules\GamingOptimize.psm1'
        Reporting      = 'Modules\Reporting.psm1'
    }

    foreach ($moduleName in $moduleFiles.Keys) {
        $modulePath = Join-Path $PSScriptRoot $moduleFiles[$moduleName]
        Import-Module $modulePath -Force -ErrorAction Stop
    }

    # Ensure utility commands remain available after nested module force-imports.
    Import-Module $utilsPath -Force -ErrorAction Stop

    $allResults = New-Object System.Collections.Generic.List[object]
    $beforeSnapshot = $null

    $startPre = Get-Date
    $preFlight = Invoke-FullPreFlight -ConfigPath $effectiveConfigPath -BackupDir $cfg.preferences.backupDirectory -SkipRestorePoint:($DryRun) -SkipRegistryBackup:($DryRun)
    $preResult = New-PreFlightModuleResult -PreFlightResult $preFlight -StartTime $startPre
    $allResults.Add($preResult) | Out-Null

    if ($null -ne $preFlight.BeforeState) {
        $beforeSnapshot = $preFlight.BeforeState
    }

    $selected = @()
    if ($ModulesOnly.Count -gt 0) {
        $selected = @($ModulesOnly | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        Write-WinCareLog -Message "ModulesOnly active: $($selected -join ', ')" -Severity Info
    }

    $executionOrder = @('RepairHealth', 'WindowsUpdate', 'SecurityScan', 'Debloat', 'AppUpdates', 'DriverGuidance', 'GamingOptimize')
    $stopOnFailure = $false
    if ($cfg.preferences.PSObject.Properties.Name -contains 'stopOnModuleFailure') {
        $stopOnFailure = [bool]$cfg.preferences.stopOnModuleFailure
    }

    $shouldContinue = $preFlight.CanProceed -or $Force
    if (-not $shouldContinue) {
        Write-WinCareLog -Message 'PreFlight blocked execution and -Force was not provided. Skipping remediation modules.' -Severity Warning
    }
    elseif ($AuditOnly) {
        Write-WinCareLog -Message 'AuditOnly enabled. Skipping remediation modules.' -Severity Info
    }
    else {
        foreach ($moduleName in $executionOrder) {
            if ($selected.Count -gt 0 -and $selected -notcontains $moduleName) {
                continue
            }

            $invokeName = "Invoke-$moduleName"
            if ($moduleName -eq 'WindowsUpdate') {
                $invokeName = 'Invoke-WindowsUpdateFix'
            }

            Write-WinCareLog -Message "Executing module: $moduleName" -Severity Info
            try {
                $result = & $invokeName -ConfigPath $effectiveConfigPath
                $allResults.Add($result) | Out-Null

                if ($result.Status -eq 'Failed' -and $stopOnFailure) {
                    Write-WinCareLog -Message "Module $moduleName failed and stopOnModuleFailure=true. Halting remaining modules." -Severity Error
                    break
                }
            }
            catch {
                $startFail = Get-Date
                $fallback = New-WinCareResult -ModuleName $moduleName -Status 'Failed' -StartTime $startFail -Details @("Unhandled exception while invoking $moduleName") -Errors @($_.Exception.Message) -ActionsAttempted 1 -ActionsCompleted 0 -ActionsFailed 1 -NextSteps @('Inspect module logs and rerun.')
                $allResults.Add($fallback) | Out-Null

                if ($stopOnFailure) {
                    break
                }
            }
        }
    }

    $resultArray = @($allResults.ToArray())
    $reportResult = Invoke-Reporting -Results $resultArray -ConfigPath $effectiveConfigPath -LogFilePath $logFile -BeforeSnapshot $beforeSnapshot
    $allResults.Add($reportResult) | Out-Null

    $failedCount = @($allResults | Where-Object { $_.Status -eq 'Failed' }).Count
    $warnCount = @($allResults | Where-Object { $_.Status -eq 'PartialSuccess' }).Count

    if ($failedCount -gt 0) {
        Write-WinCareLog -Message "WinCare completed with failures ($failedCount module(s))." -Severity Warning
        exit 2
    }
    elseif ($warnCount -gt 0) {
        Write-WinCareLog -Message "WinCare completed with warnings ($warnCount module(s) partial success)." -Severity Warning
        exit 1
    }
    else {
        Write-WinCareLog -Message 'WinCare completed successfully.' -Severity Success
        exit 0
    }
}
catch {
    if (Get-Command Write-WinCareLog -ErrorAction SilentlyContinue) {
        Write-WinCareLog -Message "WinCare orchestrator fatal error: $($_.Exception.Message)" -Severity Error
    }
    else {
        Write-Error "WinCare orchestrator fatal error: $($_.Exception.Message)"
    }
    exit 2
}
