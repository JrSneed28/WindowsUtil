Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$utilsPath = Join-Path $PSScriptRoot '..\WinCareUtils.psm1'
Import-Module $utilsPath -Force -ErrorAction Stop

function Get-WinCareAfterSnapshot {
    [CmdletBinding()]
    param()

    $snapshot = [ordered]@{
        CapturedAt       = (Get-Date).ToString('o')
        ComputerName     = $env:COMPUTERNAME
        PendingReboot    = $false
        PendingReasons   = @()
        ServicesRunning  = 0
        ServicesStopped  = 0
        DiskFreeGB       = $null
        DefenderSigVer   = $null
        PSVersionInfo    = $null
    }

    try {
        $pending = Test-PendingReboot
        $snapshot.PendingReboot = [bool]$pending.Pending
        $snapshot.PendingReasons = @($pending.Reasons)
    }
    catch {
        Write-WinCareLog -Message "AfterSnapshot: pending reboot check failed: $($_.Exception.Message)" -Severity Warning
    }

    try {
        $services = @(Get-Service -ErrorAction Stop)
        $snapshot.ServicesRunning = @($services | Where-Object { $_.Status -eq 'Running' }).Count
        $snapshot.ServicesStopped = @($services | Where-Object { $_.Status -eq 'Stopped' }).Count
    }
    catch {
        Write-WinCareLog -Message "AfterSnapshot: service inventory failed: $($_.Exception.Message)" -Severity Warning
    }

    try {
        $sysDrive = $env:SystemDrive
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$sysDrive'" -ErrorAction Stop
        if ($disk -and $disk.FreeSpace) {
            $snapshot.DiskFreeGB = [math]::Round(($disk.FreeSpace / 1GB), 2)
        }
    }
    catch {
        Write-WinCareLog -Message "AfterSnapshot: disk query failed: $($_.Exception.Message)" -Severity Warning
    }

    try {
        $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mp) {
            $snapshot.DefenderSigVer = $mp.AntivirusSignatureVersion
        }
    }
    catch {
        Write-WinCareLog -Message "AfterSnapshot: Defender status query failed: $($_.Exception.Message)" -Severity Warning
    }

    try {
        $snapshot.PSVersionInfo = Get-PSVersionInfo
    }
    catch {
        Write-WinCareLog -Message "AfterSnapshot: PowerShell version query failed: $($_.Exception.Message)" -Severity Warning
    }

    return [pscustomobject]$snapshot
}

function Invoke-Reporting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject[]]$Results,

        [Parameter()]
        [string]$ConfigPath = (Join-Path $PSScriptRoot '..\WinCare.config.json'),

        [Parameter()]
        [string]$ReportDirectory,

        [Parameter()]
        [string]$LogFilePath,

        [Parameter()]
        [pscustomobject]$BeforeSnapshot
    )

    $start = Get-Date
    $details = @()
    $errors = @()
    $undoArtifacts = @()
    $nextSteps = @()
    $attempted = 0
    $completed = 0
    $failed = 0

    try {
        $attempted++
        $cfg = Get-WinCareConfig -Path $ConfigPath
        $completed++

        $rootDir = Join-Path $PSScriptRoot '..'
        if ([string]::IsNullOrWhiteSpace($ReportDirectory)) {
            $ReportDirectory = if ($cfg.preferences.reportDirectory) { [string]$cfg.preferences.reportDirectory } else { Join-Path $rootDir 'Reports' }
        }
        if ([string]::IsNullOrWhiteSpace($LogFilePath)) {
            $logDir = if ($cfg.preferences.logDirectory) { [string]$cfg.preferences.logDirectory } else { Join-Path $rootDir 'Logs' }
            $LogFilePath = Join-Path $logDir 'WinCare.log'
        }

        if (-not (Test-Path $ReportDirectory)) {
            New-Item -Path $ReportDirectory -ItemType Directory -Force | Out-Null
        }

        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $jsonReportPath = Join-Path $ReportDirectory ("WinCare_Report_${stamp}.json")
        $textSummaryPath = Join-Path $ReportDirectory ("WinCare_Summary_${stamp}.txt")
        $afterSnapshotPath = Join-Path $ReportDirectory ("AfterSnapshot_${stamp}.json")

        $attempted++
        $afterSnapshot = Get-WinCareAfterSnapshot
        $completed++

        $attempted++
        Save-WinCareFile -Path $afterSnapshotPath -Content ($afterSnapshot | ConvertTo-Json -Depth 10)
        $undoArtifacts += $afterSnapshotPath
        $details += "After-state snapshot written: $afterSnapshotPath"
        $completed++

        $statusCounts = [ordered]@{
            Success        = @($Results | Where-Object { $_.Status -eq 'Success' }).Count
            PartialSuccess = @($Results | Where-Object { $_.Status -eq 'PartialSuccess' }).Count
            Failed         = @($Results | Where-Object { $_.Status -eq 'Failed' }).Count
            Skipped        = @($Results | Where-Object { $_.Status -eq 'Skipped' }).Count
            DryRun         = @($Results | Where-Object { $_.Status -eq 'DryRun' }).Count
        }

        $allRollback = @(@(
            $Results |
                ForEach-Object { @($_.UndoArtifacts) } |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
        ) | Sort-Object -Unique)

        $issuesFound = @(@(
            $Results |
                ForEach-Object { @($_.Errors) } |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
        ))

        $issuesRemaining = @(@(
            $Results |
                Where-Object { $_.Status -eq 'Failed' -or $_.Status -eq 'PartialSuccess' } |
                ForEach-Object {
                    "[$($_.ModuleName)] Status=$($_.Status); Errors=$(@($_.Errors).Count); NextSteps=$(@($_.NextSteps).Count)"
                }
        ))

        $beforeAfter = [ordered]@{
            Before = if ($null -ne $BeforeSnapshot) { $BeforeSnapshot } else { $null }
            After  = $afterSnapshot
        }

        $machineProfile = $null
        try {
            $machineProfile = Get-SystemProfile
        }
        catch {
            $errors += "Failed to capture system profile for report metadata: $($_.Exception.Message)"
        }

        $jsonReport = [ordered]@{
            ReportVersion        = '1.0.0'
            GeneratedAt          = (Get-Date).ToString('o')
            ComputerName         = $env:COMPUTERNAME
            LogFilePath          = $LogFilePath
            LogFileExists        = (Test-Path $LogFilePath)
            ModuleResultCounts   = $statusCounts
            ModuleResults        = $Results
            RollbackArtifacts    = $allRollback
            IssuesFound          = $issuesFound
            IssuesRemaining      = $issuesRemaining
            BeforeAfterSnapshots = $beforeAfter
            SystemProfile        = $machineProfile
        }

        $attempted++
        Save-WinCareFile -Path $jsonReportPath -Content ($jsonReport | ConvertTo-Json -Depth 20)
        $undoArtifacts += $jsonReportPath
        $details += "Structured report written: $jsonReportPath"
        $completed++

        $executiveSummary = if ($statusCounts.Failed -gt 0) {
            'WinCare completed with one or more module failures. Review issues remaining and rollback instructions before additional remediation.'
        }
        elseif ($statusCounts.PartialSuccess -gt 0) {
            'WinCare completed with partial successes. Most actions ran, but follow-up is required for unresolved items.'
        }
        else {
            'WinCare completed successfully for all executed modules. No unresolved errors were recorded in this run.'
        }

        $summaryLines = New-Object System.Collections.Generic.List[string]
        $summaryLines.Add('WinCare Execution Summary')
        $summaryLines.Add('=========================')
        $summaryLines.Add('')
        $summaryLines.Add("Generated: $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))")
        $summaryLines.Add("Computer: $env:COMPUTERNAME")
        $summaryLines.Add("")

        $summaryLines.Add('Executive Summary')
        $summaryLines.Add('-----------------')
        $summaryLines.Add($executiveSummary)
        $summaryLines.Add('')

        $summaryLines.Add('Actions Taken')
        $summaryLines.Add('-------------')
        foreach ($r in $Results) {
            $summaryLines.Add("- $($r.ModuleName): Status=$($r.Status), Attempted=$($r.ActionsAttempted), Completed=$($r.ActionsCompleted), Failed=$($r.ActionsFailed)")
        }
        $summaryLines.Add('')

        $summaryLines.Add('Issues Found')
        $summaryLines.Add('------------')
        if ($issuesFound.Count -eq 0) {
            $summaryLines.Add('- No module errors were reported.')
        }
        else {
            foreach ($issue in $issuesFound) {
                $summaryLines.Add("- $issue")
            }
        }
        $summaryLines.Add('')

        $summaryLines.Add('Issues Remaining')
        $summaryLines.Add('----------------')
        if ($issuesRemaining.Count -eq 0) {
            $summaryLines.Add('- No unresolved module statuses were detected.')
        }
        else {
            foreach ($item in $issuesRemaining) {
                $summaryLines.Add("- $item")
            }
        }
        $summaryLines.Add('')

        $summaryLines.Add('Rollback Instructions')
        $summaryLines.Add('---------------------')
        if ($allRollback.Count -eq 0) {
            $summaryLines.Add('- No rollback artifacts were recorded in this run.')
        }
        else {
            foreach ($artifact in $allRollback) {
                $summaryLines.Add("- Validate artifact exists, then restore if needed: $artifact")
            }
        }
        $summaryLines.Add('')

        $summaryLines.Add('Next Steps')
        $summaryLines.Add('----------')
        $allNext = @(@(
            $Results |
                ForEach-Object { @($_.NextSteps) } |
                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
        ) | Sort-Object -Unique)
        if ($allNext.Count -eq 0) {
            $summaryLines.Add('- No additional manual actions were suggested.')
        }
        else {
            foreach ($step in $allNext) {
                $summaryLines.Add("- $step")
            }
        }
        $summaryLines.Add('')

        $summaryLines.Add('File Manifest')
        $summaryLines.Add('-------------')
        $summaryLines.Add("- Log file: $LogFilePath")
        $summaryLines.Add("- After snapshot: $afterSnapshotPath")
        $summaryLines.Add("- Structured report: $jsonReportPath")
        $summaryLines.Add("- Summary report: $textSummaryPath")

        $attempted++
        Save-WinCareFile -Path $textSummaryPath -Content ($summaryLines -join [Environment]::NewLine)
        $undoArtifacts += $textSummaryPath
        $details += "Summary report written: $textSummaryPath"
        $completed++

        $isDryRun = $false
        if ($cfg.preferences.PSObject.Properties.Name -contains 'dryRun') {
            $isDryRun = [bool]$cfg.preferences.dryRun
        }

        if (-not (Test-Path $LogFilePath)) {
            if ($isDryRun) {
                $details += "Unified log file not present in dry-run mode (expected when WhatIf suppresses writes): $LogFilePath"
            }
            else {
                $failed++
                $errors += "Expected unified log file not found: $LogFilePath"
                $nextSteps += 'Configure log file path before execution and verify logging setup in orchestrator.'
            }
        }
        else {
            $details += "Unified log file verified: $LogFilePath"
        }

        $status = if ($failed -eq 0) { 'Success' } elseif ($completed -gt 0) { 'PartialSuccess' } else { 'Failed' }
        return New-WinCareResult -ModuleName 'Reporting' -Status $status -StartTime $start -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps $nextSteps -ActionsAttempted $attempted -ActionsCompleted $completed -ActionsFailed $failed
    }
    catch {
        $errors += $_.Exception.Message
        return New-WinCareResult -ModuleName 'Reporting' -Status 'Failed' -StartTime $start -Details $details -Errors $errors -UndoArtifacts $undoArtifacts -NextSteps $nextSteps -ActionsAttempted $attempted -ActionsCompleted $completed -ActionsFailed ($failed + 1)
    }
}

Export-ModuleMember -Function Invoke-Reporting
