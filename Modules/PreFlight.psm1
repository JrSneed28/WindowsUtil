<#
.SYNOPSIS
    WinCare PreFlight Module — Safety checks, restore point, registry backup,
    before-state snapshot.

.DESCRIPTION
    Runs 10 safety/readiness checks before any WinCare module executes.
    Creates a system restore point, backs up critical registry hives,
    and captures a before-state snapshot for comparison after operations.

    This module is the mandatory gatekeeper for Phase 2.

.NOTES
    Author  : WinCare Project
    Phase   : 2 (Pre-Execution)
    Safety  : Creates backups, never modifies system state beyond restore points
    Citation: [MS Learn] Checkpoint-Computer, reg.exe export, Get-ComputerRestorePoint
#>

#Requires -Version 5.1

# Import shared utilities
$utilsPath = Join-Path $PSScriptRoot '..\WinCareUtils.psm1'
if (Test-Path $utilsPath) {
    Import-Module $utilsPath -Force -ErrorAction Stop
}

function Invoke-PreFlightChecks {
    <#
    .SYNOPSIS
        Runs all pre-flight safety checks and returns pass/fail results.

    .DESCRIPTION
        Executes 10 readiness checks:
          1. Administrator privileges
          2. Pending reboot
          3. Disk space (>= 2 GB free on system drive)
          4. PowerShell version (>= 5.1)
          5. Config file validity
          6. System restore service status
          7. DISM availability
          8. SFC availability
          9. WinGet availability (informational)
         10. Battery/power status (laptops)

        Returns an array of check result objects. Critical failures block execution.

    .PARAMETER ConfigPath
        Path to the WinCare config JSON file.

    .PARAMETER SkipAdminCheck
        Skip the administrator privilege check (for testing only).

    .OUTPUTS
        [PSCustomObject[]] Array of check results with Name, Status, Critical, Message.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [switch]$SkipAdminCheck
    )

    $results = @()

    # Check 1 — Administrator
    $adminCheck = [PSCustomObject]@{
        Name     = 'Administrator'
        Status   = 'Fail'
        Critical = $true
        Message  = ''
    }
    if ($SkipAdminCheck) {
        $adminCheck.Status  = 'Skip'
        $adminCheck.Message = 'Admin check skipped (testing mode)'
        $adminCheck.Critical = $false
    }
    elseif (Test-IsAdministrator) {
        $adminCheck.Status  = 'Pass'
        $adminCheck.Message = 'Running with administrator privileges'
    }
    else {
        $adminCheck.Message = 'WinCare requires administrator privileges for most operations'
    }
    $results += $adminCheck

    # Check 2 — Pending Reboot
    $rebootCheck = [PSCustomObject]@{
        Name     = 'PendingReboot'
        Status   = 'Pass'
        Critical = $false
        Message  = 'No pending reboot detected'
    }
    if (Test-PendingReboot) {
        $rebootCheck.Status  = 'Warn'
        $rebootCheck.Message = 'Pending reboot detected — some operations may not complete correctly'
    }
    $results += $rebootCheck

    # Check 3 — Disk Space
    $diskCheck = [PSCustomObject]@{
        Name     = 'DiskSpace'
        Status   = 'Fail'
        Critical = $true
        Message  = ''
    }
    try {
        $sysDrive = $env:SystemDrive
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$sysDrive'" -ErrorAction Stop
        $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        if ($freeGB -ge 2) {
            $diskCheck.Status  = 'Pass'
            $diskCheck.Message = "System drive $sysDrive has $freeGB GB free"
        }
        else {
            $diskCheck.Message = "System drive $sysDrive has only $freeGB GB free (minimum 2 GB required)"
        }
    }
    catch {
        $diskCheck.Message = "Could not check disk space: $($_.Exception.Message)"
    }
    $results += $diskCheck

    # Check 4 — PowerShell Version
    $psCheck = [PSCustomObject]@{
        Name     = 'PSVersion'
        Status   = 'Fail'
        Critical = $true
        Message  = ''
    }
    $psVer = $PSVersionTable.PSVersion
    if ($psVer.Major -ge 5 -and $psVer.Minor -ge 1 -or $psVer.Major -ge 7) {
        $psCheck.Status  = 'Pass'
        $psCheck.Message = "PowerShell $($psVer.ToString()) detected"
    }
    else {
        $psCheck.Message = "PowerShell $($psVer.ToString()) is below minimum 5.1"
    }
    $results += $psCheck

    # Check 5 — Config File
    $cfgCheck = [PSCustomObject]@{
        Name     = 'ConfigFile'
        Status   = 'Fail'
        Critical = $true
        Message  = ''
    }
    if ([string]::IsNullOrEmpty($ConfigPath)) {
        $cfgCheck.Status  = 'Skip'
        $cfgCheck.Message = 'No config path specified'
        $cfgCheck.Critical = $false
    }
    elseif (-not (Test-Path $ConfigPath)) {
        $cfgCheck.Message = "Config file not found: $ConfigPath"
    }
    else {
        try {
            $null = Get-Content $ConfigPath -Raw | ConvertFrom-Json -ErrorAction Stop
            $cfgCheck.Status  = 'Pass'
            $cfgCheck.Message = "Config file valid: $ConfigPath"
        }
        catch {
            $cfgCheck.Message = "Config file is invalid JSON: $($_.Exception.Message)"
        }
    }
    $results += $cfgCheck

    # Check 6 — System Restore Service
    $srCheck = [PSCustomObject]@{
        Name     = 'SystemRestore'
        Status   = 'Warn'
        Critical = $false
        Message  = ''
    }
    try {
        $srService = Get-Service -Name 'srservice' -ErrorAction SilentlyContinue
        if ($srService -and $srService.Status -eq 'Running') {
            $srCheck.Status  = 'Pass'
            $srCheck.Message = 'System Restore service is running'
        }
        elseif ($srService) {
            $srCheck.Message = "System Restore service exists but status is $($srService.Status)"
        }
        else {
            $srCheck.Message = 'System Restore service not found'
        }
    }
    catch {
        $srCheck.Message = "Could not check System Restore: $($_.Exception.Message)"
    }
    $results += $srCheck

    # Check 7 — DISM availability
    $dismCheck = [PSCustomObject]@{
        Name     = 'DISM'
        Status   = 'Fail'
        Critical = $false
        Message  = ''
    }
    $dismPath = Get-Command dism.exe -ErrorAction SilentlyContinue
    if ($dismPath) {
        $dismCheck.Status  = 'Pass'
        $dismCheck.Message = "DISM found: $($dismPath.Source)"
    }
    else {
        $dismCheck.Message = 'DISM not found in PATH'
    }
    $results += $dismCheck

    # Check 8 — SFC availability
    $sfcCheck = [PSCustomObject]@{
        Name     = 'SFC'
        Status   = 'Fail'
        Critical = $false
        Message  = ''
    }
    $sfcPath = Get-Command sfc.exe -ErrorAction SilentlyContinue
    if ($sfcPath) {
        $sfcCheck.Status  = 'Pass'
        $sfcCheck.Message = "SFC found: $($sfcPath.Source)"
    }
    else {
        $sfcCheck.Message = 'SFC not found in PATH'
    }
    $results += $sfcCheck

    # Check 9 — WinGet availability (informational)
    $wgCheck = [PSCustomObject]@{
        Name     = 'WinGet'
        Status   = 'Info'
        Critical = $false
        Message  = ''
    }
    $wgPath = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($wgPath) {
        $wgVer = try { (winget --version 2>&1) -replace '[^\d.]', '' } catch { 'unknown' }
        $wgCheck.Status  = 'Pass'
        $wgCheck.Message = "WinGet v$wgVer available"
    }
    else {
        $wgCheck.Message = 'WinGet not installed — AppUpdates module will be limited'
    }
    $results += $wgCheck

    # Check 10 — Battery/Power (laptops)
    $pwrCheck = [PSCustomObject]@{
        Name     = 'PowerStatus'
        Status   = 'Pass'
        Critical = $false
        Message  = 'Desktop system or AC power detected'
    }
    try {
        $battery = Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue
        if ($battery) {
            $charge = $battery.EstimatedChargeRemaining
            $onAC = ($battery.BatteryStatus -eq 2) # 2 = AC power
            if (-not $onAC -and $charge -lt 20) {
                $pwrCheck.Status  = 'Warn'
                $pwrCheck.Message = "Battery at ${charge}% and not on AC power - plug in before running repairs"
            }
            elseif (-not $onAC) {
                $pwrCheck.Status  = 'Warn'
                $pwrCheck.Message = "Running on battery (${charge}%) - AC power recommended"
            }
            else {
                $pwrCheck.Message = "Laptop on AC power (${charge}% charge)"
            }
        }
    }
    catch {
        $pwrCheck.Message = "Could not check power status: $($_.Exception.Message)"
    }
    $results += $pwrCheck

    return $results
}

function New-WinCareRestorePoint {
    <#
    .SYNOPSIS
        Creates a system restore point before WinCare operations.

    .DESCRIPTION
        Wraps Checkpoint-Computer with error handling and frequency bypass.
        On Windows 10/11, restore points are throttled to once per 24 hours
        unless the SystemRestorePointCreationFrequency registry value is set.

    .PARAMETER Description
        Description for the restore point. Defaults to "WinCare Pre-Operation Snapshot".

    .OUTPUTS
        [PSCustomObject] with Status, Message, RestorePointID properties.

    .NOTES
        Citation: [MS Learn] Checkpoint-Computer
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/checkpoint-computer
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Description = 'WinCare Pre-Operation Snapshot'
    )

    $result = [PSCustomObject]@{
        Status         = 'Failed'
        Message        = ''
        RestorePointID = $null
    }

    if (-not (Test-IsAdministrator)) {
        $result.Message = 'Cannot create restore point without administrator privileges'
        Write-WinCareLog $result.Message -Severity Warning
        return $result
    }

    try {
        # Allow frequent restore points by temporarily setting frequency to 0
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        $originalFreq = $null
        try {
            $originalFreq = (Get-ItemProperty $regPath -Name SystemRestorePointCreationFrequency -ErrorAction SilentlyContinue).SystemRestorePointCreationFrequency
        } catch {}

        Set-ItemProperty -Path $regPath -Name SystemRestorePointCreationFrequency -Value 0 -Type DWord -ErrorAction SilentlyContinue

        # Get restore points before
        $beforePoints = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue)

        # Create the restore point
        Write-WinCareLog "Creating system restore point: $Description"
        Checkpoint-Computer -Description $Description -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop

        # Get restore points after to find our new one
        $afterPoints = @(Get-ComputerRestorePoint -ErrorAction SilentlyContinue)
        $newPoint = $afterPoints | Where-Object { $_.SequenceNumber -notin $beforePoints.SequenceNumber } | Select-Object -Last 1

        if ($newPoint) {
            $result.Status = 'Success'
            $result.RestorePointID = $newPoint.SequenceNumber
            $result.Message = "Restore point created: #$($newPoint.SequenceNumber) - $Description"
        }
        else {
            $result.Status = 'Success'
            $result.Message = "Restore point created: $Description (ID could not be confirmed)"
        }

        # Restore original frequency value
        if ($null -ne $originalFreq) {
            Set-ItemProperty -Path $regPath -Name SystemRestorePointCreationFrequency -Value $originalFreq -Type DWord -ErrorAction SilentlyContinue
        }
        else {
            Remove-ItemProperty -Path $regPath -Name SystemRestorePointCreationFrequency -ErrorAction SilentlyContinue
        }

        Write-WinCareLog $result.Message -Severity Info
    }
    catch {
        $result.Message = "Failed to create restore point: $($_.Exception.Message)"
        Write-WinCareLog $result.Message -Severity Error
    }

    return $result
}

function Backup-CriticalRegistry {
    <#
    .SYNOPSIS
        Backs up critical registry hives to the Backups directory.

    .DESCRIPTION
        Exports HKLM\SOFTWARE, HKLM\SYSTEM, and HKCU to .reg files
        in the Backups directory with timestamped filenames.

    .PARAMETER BackupDir
        Directory to store backups. Defaults to .\Backups under project root.

    .OUTPUTS
        [PSCustomObject] with Status, BackupFiles (array of paths), Message.

    .NOTES
        Citation: [MS Learn] reg.exe export
        https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-export
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$BackupDir = (Join-Path $PSScriptRoot '..\Backups')
    )

    $result = [PSCustomObject]@{
        Status      = 'Failed'
        BackupFiles = @()
        Message     = ''
    }

    if (-not (Test-Path $BackupDir)) {
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    }

    $timestamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $hives = @(
        @{ Key = 'HKLM\SOFTWARE'; File = "HKLM_SOFTWARE_$timestamp.reg" }
        @{ Key = 'HKLM\SYSTEM';   File = "HKLM_SYSTEM_$timestamp.reg" }
        @{ Key = 'HKCU';          File = "HKCU_$timestamp.reg" }
    )

    $exported = @()
    $errors = @()

    foreach ($hive in $hives) {
        $outFile = Join-Path $BackupDir $hive.File
        Write-WinCareLog "Backing up registry: $($hive.Key) -> $outFile"
        try {
            $regResult = Export-RegistryBackup -KeyPath $hive.Key -OutputPath $outFile
            if (Test-Path $outFile) {
                $exported += $outFile
                Write-WinCareLog "  Backed up: $($hive.Key)" -Severity Info
            }
            else {
                $errors += "Failed to export $($hive.Key)"
                Write-WinCareLog "  Failed: $($hive.Key)" -Severity Warning
            }
        }
        catch {
            $errors += "Error exporting $($hive.Key): $($_.Exception.Message)"
            Write-WinCareLog "  Error: $($hive.Key) - $($_.Exception.Message)" -Severity Error
        }
    }

    $result.BackupFiles = $exported

    if ($exported.Count -eq $hives.Count) {
        $result.Status  = 'Success'
        $result.Message = "All $($hives.Count) registry hives backed up successfully"
    }
    elseif ($exported.Count -gt 0) {
        $result.Status  = 'Partial'
        $result.Message = "$($exported.Count)/$($hives.Count) hives backed up. Errors: $($errors -join '; ')"
    }
    else {
        $result.Message = "No hives backed up. Errors: $($errors -join '; ')"
    }

    Write-WinCareLog $result.Message -Severity $(if ($result.Status -eq 'Success') { 'Info' } else { 'Warning' })
    return $result
}

function Get-BeforeStateSnapshot {
    <#
    .SYNOPSIS
        Captures a before-state snapshot for comparison after WinCare operations.

    .DESCRIPTION
        Records key system metrics before operations begin:
        - Running services count and list
        - Installed AppX package count
        - Startup items count
        - Disk space on system drive
        - Defender signature version
        - Environment variable snapshot

    .OUTPUTS
        [PSCustomObject] Before-state snapshot object.
    #>
    [CmdletBinding()]
    param()

    Write-WinCareLog "Capturing before-state snapshot..."

    $snapshot = [PSCustomObject]@{
        Timestamp       = (Get-Date).ToString('o')
        RunningServices = @()
        ServiceCount    = 0
        AppXCount       = 0
        StartupCount    = 0
        DiskFree_GB     = 0
        DefenderSigVer  = ''
        EnvVars         = @{}
    }

    # Services
    try {
        $services = Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object -ExpandProperty Name
        $snapshot.RunningServices = $services
        $snapshot.ServiceCount    = $services.Count
    } catch {
        Write-WinCareLog "Could not snapshot services: $($_.Exception.Message)" -Severity Warning
    }

    # AppX count
    try {
        $snapshot.AppXCount = @(Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object { -not $_.IsFramework }).Count
    } catch {
        Write-WinCareLog "Could not snapshot AppX count: $($_.Exception.Message)" -Severity Warning
    }

    # Startup count
    try {
        $runKeys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
        )
        $count = 0
        foreach ($key in $runKeys) {
            if (Test-Path $key) {
                $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
                $count += ($props.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSProvider','PSDrive') }).Count
            }
        }
        $snapshot.StartupCount = $count
    } catch {
        Write-WinCareLog "Could not snapshot startup items: $($_.Exception.Message)" -Severity Warning
    }

    # Disk space
    try {
        $sysDrive = $env:SystemDrive
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$sysDrive'" -ErrorAction Stop
        $snapshot.DiskFree_GB = [math]::Round($disk.FreeSpace / 1GB, 2)
    } catch {
        Write-WinCareLog "Could not snapshot disk space: $($_.Exception.Message)" -Severity Warning
    }

    # Defender
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mpStatus) {
            $snapshot.DefenderSigVer = $mpStatus.AntivirusSignatureVersion
        }
    } catch {
        Write-WinCareLog "Could not snapshot Defender status: $($_.Exception.Message)" -Severity Warning
    }

    # Key environment variables
    try {
        $snapshot.EnvVars = @{
            PATH   = $env:PATH
            TEMP   = $env:TEMP
            COMSPEC = $env:COMSPEC
        }
    } catch {}

    Write-WinCareLog "Before-state snapshot captured (Services: $($snapshot.ServiceCount), AppX: $($snapshot.AppXCount), Disk: $($snapshot.DiskFree_GB) GB free)"
    return $snapshot
}

function Invoke-FullPreFlight {
    <#
    .SYNOPSIS
        Runs the complete pre-flight sequence: checks, restore point, registry backup, snapshot.

    .DESCRIPTION
        Orchestrates the full pre-flight sequence in order:
        1. Run all 10 safety checks
        2. Abort if any critical check fails
        3. Create system restore point
        4. Backup critical registry hives
        5. Capture before-state snapshot

        Returns a comprehensive result object for the orchestrator.

    .PARAMETER ConfigPath
        Path to WinCare config JSON file.

    .PARAMETER BackupDir
        Directory for registry backups.

    .PARAMETER SkipRestorePoint
        Skip restore point creation (for testing/dry-run).

    .PARAMETER SkipRegistryBackup
        Skip registry backup (for testing/dry-run).

    .OUTPUTS
        [PSCustomObject] with Checks, RestorePoint, RegistryBackup, BeforeState, CanProceed.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ConfigPath,

        [Parameter()]
        [string]$BackupDir = (Join-Path $PSScriptRoot '..\Backups'),

        [Parameter()]
        [switch]$SkipRestorePoint,

        [Parameter()]
        [switch]$SkipRegistryBackup
    )

    Write-WinCareLog "=== Starting Pre-Flight Sequence ==="

    $pfResult = [PSCustomObject]@{
        Checks         = @()
        RestorePoint   = $null
        RegistryBackup = $null
        BeforeState    = $null
        CanProceed     = $false
        BlockReasons   = @()
        StartTime      = (Get-Date)
        EndTime        = $null
    }

    # Step 1 - Safety checks
    Write-WinCareLog "Step 1/4: Running safety checks..."
    $pfResult.Checks = Invoke-PreFlightChecks -ConfigPath $ConfigPath

    # Evaluate critical failures
    $criticalFails = $pfResult.Checks | Where-Object { $_.Critical -and $_.Status -eq 'Fail' }
    if ($criticalFails) {
        foreach ($fail in $criticalFails) {
            $pfResult.BlockReasons += "CRITICAL: $($fail.Name) - $($fail.Message)"
            Write-WinCareLog "BLOCKED: $($fail.Name) - $($fail.Message)" -Severity Warning
        }
        $pfResult.EndTime = Get-Date
        Write-WinCareLog "=== Pre-Flight FAILED - $($criticalFails.Count) critical check(s) failed ==="
        return $pfResult
    }

    # Step 2 — Restore point
    if ($SkipRestorePoint) {
        Write-WinCareLog "Step 2/4: Restore point creation SKIPPED (flag set)"
        $pfResult.RestorePoint = [PSCustomObject]@{
            Status = 'Skipped'; Message = 'Skipped by flag'; RestorePointID = $null
        }
    }
    else {
        Write-WinCareLog "Step 2/4: Creating restore point..."
        $pfResult.RestorePoint = New-WinCareRestorePoint
    }

    # Step 3 — Registry backup
    if ($SkipRegistryBackup) {
        Write-WinCareLog "Step 3/4: Registry backup SKIPPED (flag set)"
        $pfResult.RegistryBackup = [PSCustomObject]@{
            Status = 'Skipped'; BackupFiles = @(); Message = 'Skipped by flag'
        }
    }
    else {
        Write-WinCareLog "Step 3/4: Backing up registry..."
        $pfResult.RegistryBackup = Backup-CriticalRegistry -BackupDir $BackupDir
    }

    # Step 4 — Before-state snapshot
    Write-WinCareLog "Step 4/4: Capturing before-state..."
    $pfResult.BeforeState = Get-BeforeStateSnapshot

    $pfResult.CanProceed = $true
    $pfResult.EndTime    = Get-Date

    $duration = ($pfResult.EndTime - $pfResult.StartTime).TotalSeconds
    Write-WinCareLog "=== Pre-Flight PASSED in $([math]::Round($duration,1))s ==="

    return $pfResult
}

# Export module members
Export-ModuleMember -Function @(
    'Invoke-PreFlightChecks'
    'New-WinCareRestorePoint'
    'Backup-CriticalRegistry'
    'Get-BeforeStateSnapshot'
    'Invoke-FullPreFlight'
)
