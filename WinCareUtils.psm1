<#
.SYNOPSIS
    WinCare shared utility module — logging, config, system profiling, and helper functions.
.DESCRIPTION
    Provides foundational functions used by all WinCare modules:
    - Structured dual-output logging (console + file)
    - Standardised result objects
    - Configuration loading and validation
    - System compatibility profiling
    - Registry backup, retry logic, and safety checks
.NOTES
    Author : WinCare Project
    Version: 1.0.0
    Requires: PowerShell 5.1+
#>

#Requires -Version 5.1

# ─────────────────────────────────────────────────────────────────────
# Module-scoped state
# ─────────────────────────────────────────────────────────────────────
$script:WinCareVersion = '1.0.0'
$script:LogFilePath    = $null

# ─────────────────────────────────────────────────────────────────────
# 1. Write-WinCareLog
# ─────────────────────────────────────────────────────────────────────
function Write-WinCareLog {
    <#
    .SYNOPSIS
        Writes a timestamped, severity-tagged log entry to both the console and a log file.
    .PARAMETER Message
        The log message text.
    .PARAMETER Severity
        Log severity: Info, Warning, Error, Success, Debug.
    .PARAMETER LogFile
        Optional override for the log file path. If omitted, uses the module-scoped path.
    .EXAMPLE
        Write-WinCareLog -Message "SFC scan started" -Severity Info
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Info','Warning','Error','Success','Debug')]
        [string]$Severity = 'Info',

        [string]$LogFile
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $tag       = $Severity.ToUpper().PadRight(7)
    $entry     = "[$timestamp] [$tag] $Message"

    # Resolve log file
    $targetLog = if ($LogFile) { $LogFile }
                 elseif ($script:LogFilePath) { $script:LogFilePath }
                 else { $null }

    # Console output via appropriate stream (never Write-Host)
    switch ($Severity) {
        'Error'   { Write-Error   -Message $Message -ErrorAction Continue }
        'Warning' { Write-Warning -Message $Message }
        'Debug'   { Write-Debug   -Message $Message }
        default   { Write-Information -MessageData $entry -InformationAction Continue }
    }

    # File output
    if ($targetLog) {
        $dir = Split-Path $targetLog -Parent
        if ($dir -and -not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        # UTF-8 with BOM for consistency
        $entry | Out-File -FilePath $targetLog -Append -Encoding utf8
    }
}

function Set-WinCareLogFile {
    <#
    .SYNOPSIS
        Sets the module-scoped default log file path.
    .PARAMETER Path
        Full path to the log file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    $script:LogFilePath = $Path
}

# ─────────────────────────────────────────────────────────────────────
# 2. New-WinCareResult
# ─────────────────────────────────────────────────────────────────────
function New-WinCareResult {
    <#
    .SYNOPSIS
        Creates a standardised PSCustomObject representing a module's execution result.
    .PARAMETER ModuleName
        Name of the module that produced the result.
    .PARAMETER Status
        Overall status: Success, PartialSuccess, Failed, Skipped, DryRun.
    .PARAMETER StartTime
        When the module began execution.
    .PARAMETER Details
        Array of detail strings describing actions taken.
    .PARAMETER Errors
        Array of error strings encountered.
    .PARAMETER UndoArtifacts
        Array of paths/identifiers for rollback artifacts.
    .PARAMETER NextSteps
        Array of recommended follow-up actions.
    .PARAMETER ActionsAttempted
        Number of actions attempted.
    .PARAMETER ActionsCompleted
        Number of actions completed successfully.
    .PARAMETER ActionsFailed
        Number of actions that failed.
    .EXAMPLE
        $result = New-WinCareResult -ModuleName 'RepairHealth' -Status 'Success' -StartTime $start
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ModuleName,

        [Parameter(Mandatory)]
        [ValidateSet('Success','PartialSuccess','Failed','Skipped','DryRun')]
        [string]$Status,

        [Parameter(Mandatory)]
        [datetime]$StartTime,

        [string[]]$Details        = @(),
        [string[]]$Errors         = @(),
        [string[]]$UndoArtifacts  = @(),
        [string[]]$NextSteps      = @(),
        [int]$ActionsAttempted     = 0,
        [int]$ActionsCompleted    = 0,
        [int]$ActionsFailed       = 0
    )

    $endTime  = Get-Date
    $duration = $endTime - $StartTime

    [PSCustomObject]@{
        ModuleName       = $ModuleName
        Status           = $Status
        StartTime        = $StartTime
        EndTime          = $endTime
        Duration         = $duration
        ActionsAttempted = $ActionsAttempted
        ActionsCompleted = $ActionsCompleted
        ActionsFailed    = $ActionsFailed
        Details          = $Details
        Errors           = $Errors
        UndoArtifacts    = $UndoArtifacts
        NextSteps        = $NextSteps
    }
}

# ─────────────────────────────────────────────────────────────────────
# 3. Get-WinCareConfig
# ─────────────────────────────────────────────────────────────────────
function Get-WinCareConfig {
    <#
    .SYNOPSIS
        Loads and validates WinCare.config.json.
    .PARAMETER Path
        Path to the JSON configuration file.
    .OUTPUTS
        PSCustomObject representing the validated configuration.
    .EXAMPLE
        $cfg = Get-WinCareConfig -Path ".\WinCare.config.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        throw "Configuration file not found: $Path"
    }

    try {
        $raw = Get-Content -Path $Path -Raw -Encoding UTF8
        $config = $raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Failed to parse configuration JSON: $($_.Exception.Message)"
    }

    $requiredKeys = @('version', 'modules', 'debloat', 'preferences')
    foreach ($key in $requiredKeys) {
        if (-not ($config.PSObject.Properties.Name -contains $key)) {
            throw "Configuration missing required key: '$key'"
        }
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

    $hasExclusions = $false
    if ($null -ne $config.debloat) {
        $hasExclusions = ($config.debloat.PSObject.Properties.Name -contains 'hardcodedExclusions')
    }

    if ($hasExclusions) {
        $existingExclusions = @($config.debloat.hardcodedExclusions)
        foreach ($pkg in $requiredExclusions) {
            $found = $false
            foreach ($existing in $existingExclusions) {
                if ($existing -eq $pkg) {
                    $found = $true
                    break
                }

                if ($pkg.Contains('*') -and $existing -like $pkg) {
                    $found = $true
                    break
                }

                if ($existing.Contains('*') -and $pkg -like $existing) {
                    $found = $true
                    break
                }
            }

            if (-not $found) {
                Write-WinCareLog -Message "Config warning: hardcoded exclusion '$pkg' not found; it will still be enforced at runtime." -Severity Warning
            }
        }
    }
    else {
        Write-WinCareLog -Message "Config missing 'debloat.hardcodedExclusions'; hardcoded exclusions will be enforced at runtime." -Severity Warning
    }

    return $config
}

# ─────────────────────────────────────────────────────────────────────
# 4. Save-WinCareFile
# ─────────────────────────────────────────────────────────────────────
function Save-WinCareFile {
    <#
    .SYNOPSIS
        Saves content to a file using UTF-8 with BOM encoding.
    .PARAMETER Path
        Destination file path.
    .PARAMETER Content
        String content to write.
    .PARAMETER Append
        If set, appends to the file instead of overwriting.
    .EXAMPLE
        Save-WinCareFile -Path ".\report.txt" -Content $reportText
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Content,

        [switch]$Append
    )

    $dir = Split-Path $Path -Parent
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    if ($Append) {
        $Content | Out-File -FilePath $Path -Append -Encoding utf8
    }
    else {
        $Content | Out-File -FilePath $Path -Encoding utf8
    }
}

# ─────────────────────────────────────────────────────────────────────
# 5. Test-IsAdministrator
# ─────────────────────────────────────────────────────────────────────
function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Returns $true if the current session is running elevated (Administrator).
    .EXAMPLE
        if (-not (Test-IsAdministrator)) { Write-Warning "Elevation required." }
    #>
    [CmdletBinding()]
    param()

    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ─────────────────────────────────────────────────────────────────────
# 6. Test-PendingReboot
# ─────────────────────────────────────────────────────────────────────
function Test-PendingReboot {
    <#
    .SYNOPSIS
        Checks multiple registry locations for a pending reboot condition.
    .OUTPUTS
        PSCustomObject with Pending (bool), Reasons (string[]).
    .NOTES
        Citation: [MS Learn] Registry keys indicating pending restart
        https://learn.microsoft.com/en-us/windows/deployment/update/how-windows-update-works
    .EXAMPLE
        $reboot = Test-PendingReboot
        if ($reboot.Pending) { Write-Warning "Reboot pending: $($reboot.Reasons -join ', ')" }
    #>
    [CmdletBinding()]
    param()

    $reasons = [System.Collections.Generic.List[string]]::new()

    # Component-Based Servicing
    $cbsKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    if (Test-Path $cbsKey) {
        $reasons.Add('Component Based Servicing')
    }

    # Windows Update
    $wuKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    if (Test-Path $wuKey) {
        $reasons.Add('Windows Update')
    }

    # Pending file rename operations
    $pfroKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    try {
        $pfro = Get-ItemProperty -Path $pfroKey -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
        if ($pfro -and $pfro.PendingFileRenameOperations) {
            $reasons.Add('Pending File Rename Operations')
        }
    }
    catch { }

    # Computer rename pending
    $activeKey  = 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName'
    $pendingKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName'
    try {
        $active  = (Get-ItemProperty -Path $activeKey  -Name 'ComputerName' -ErrorAction SilentlyContinue).ComputerName
        $pending = (Get-ItemProperty -Path $pendingKey -Name 'ComputerName' -ErrorAction SilentlyContinue).ComputerName
        if ($active -and $pending -and ($active -ne $pending)) {
            $reasons.Add('Computer Rename Pending')
        }
    }
    catch { }

    [PSCustomObject]@{
        Pending = ($reasons.Count -gt 0)
        Reasons = $reasons.ToArray()
    }
}

# ─────────────────────────────────────────────────────────────────────
# 7. Get-SystemProfile
# ─────────────────────────────────────────────────────────────────────
function Get-SystemProfile {
    <#
    .SYNOPSIS
        Builds a compatibility matrix of the current system for conditional module logic.
    .DESCRIPTION
        Detects edition, architecture, domain join status, management tools, virtualisation,
        hardware class, disk space, AV status, and PowerShell version — all read-only.
    .OUTPUTS
        PSCustomObject with 17 boolean/string properties.
    .NOTES
        Citation: [MS Learn] Get-CimInstance, Win32_OperatingSystem, Win32_ComputerSystem
        https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/get-ciminstance
    .EXAMPLE
        $profile = Get-SystemProfile
        if ($profile.IsLTSC) { Write-Information "LTSC detected — skipping Store debloat" }
    #>
    [CmdletBinding()]
    param()

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem  -ErrorAction SilentlyContinue

    # Edition detection
    $edition = if ($os) { $os.Caption } else { 'Unknown' }
    $isHome   = $edition -match 'Home'
    $isLTSC   = $edition -match 'LTSC|LTSB'

    # Architecture
    $isARM64  = $env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or
                (Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue |
                 Select-Object -First 1 -ExpandProperty Architecture -ErrorAction SilentlyContinue) -eq 12

    # Domain / management
    $isDomainJoined = if ($cs) { $cs.PartOfDomain } else { $false }

    $isEntraJoined = $false
    try {
        $dsregOutput = dsregcmd /status 2>$null
        if ($dsregOutput -match 'AzureAdJoined\s*:\s*YES') {
            $isEntraJoined = $true
        }
    }
    catch { }

    $isWSUSManaged = $false
    $wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    if (Test-Path $wuKey) {
        $wuServer = Get-ItemProperty -Path $wuKey -Name 'WUServer' -ErrorAction SilentlyContinue
        if ($wuServer -and $wuServer.WUServer) {
            $isWSUSManaged = $true
        }
    }

    $isIntuneManaged = $false
    $intuneKey = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (Test-Path $intuneKey) {
        $enrollments = Get-ChildItem $intuneKey -ErrorAction SilentlyContinue
        if ($enrollments.Count -gt 0) {
            $isIntuneManaged = $true
        }
    }

    # Virtualisation
    $isVM = $false
    if ($cs) {
        $isVM = $cs.Model -match 'Virtual|VMware|VirtualBox|Hyper-V|QEMU|Xen|Parallels' -or
                $cs.Manufacturer -match 'Microsoft Corporation|VMware|innotek|Xen|QEMU|Parallels'
    }

    # Laptop detection
    $isLaptop = $false
    try {
        $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
        if ($battery) { $isLaptop = $true }
    }
    catch { }
    if (-not $isLaptop -and $cs) {
        # Chassis types: 8=Portable, 9=Laptop, 10=Notebook, 14=Sub Notebook, 31=Convertible, 32=Detachable
        try {
            $chassis = Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction SilentlyContinue
            if ($chassis) {
                $laptopTypes = @(8, 9, 10, 14, 31, 32)
                foreach ($ct in $chassis.ChassisTypes) {
                    if ($ct -in $laptopTypes) { $isLaptop = $true; break }
                }
            }
        }
        catch { }
    }

    # Disk space (system drive)
    $hasLowDiskSpace = $false
    try {
        $sysDrive = $env:SystemDrive
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$sysDrive'" -ErrorAction SilentlyContinue
        if ($disk -and $disk.FreeSpace) {
            $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
            if ($freeGB -lt 10) { $hasLowDiskSpace = $true }
        }
    }
    catch { }

    # Pending reboot
    $rebootCheck    = Test-PendingReboot
    $hasPendingReboot = $rebootCheck.Pending

    # Third-party AV
    $hasThirdPartyAV = $false
    try {
        $avProducts = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
        if ($avProducts) {
            foreach ($av in $avProducts) {
                if ($av.displayName -notmatch 'Windows Defender|Microsoft Defender') {
                    $hasThirdPartyAV = $true
                    break
                }
            }
        }
    }
    catch { }

    # PowerShell version
    $psVersion = $PSVersionTable.PSVersion.ToString()
    $psEdition = if ($PSVersionTable.PSEdition) { $PSVersionTable.PSEdition } else { 'Desktop' }
    $is7Plus   = $PSVersionTable.PSVersion.Major -ge 7

    [PSCustomObject]@{
        Edition          = $edition
        IsHome           = [bool]$isHome
        IsLTSC           = [bool]$isLTSC
        IsARM64          = [bool]$isARM64
        IsDomainJoined   = [bool]$isDomainJoined
        IsEntraJoined    = [bool]$isEntraJoined
        IsWSUSManaged    = [bool]$isWSUSManaged
        IsIntuneManaged  = [bool]$isIntuneManaged
        IsVM             = [bool]$isVM
        IsLaptop         = [bool]$isLaptop
        HasLowDiskSpace  = [bool]$hasLowDiskSpace
        HasPendingReboot = [bool]$hasPendingReboot
        HasThirdPartyAV  = [bool]$hasThirdPartyAV
        PSVersion        = $psVersion
        PSEdition        = $psEdition
        Is7Plus          = [bool]$is7Plus
        WinCareVersion   = $script:WinCareVersion
    }
}

# ─────────────────────────────────────────────────────────────────────
# 8. Invoke-WithRetry
# ─────────────────────────────────────────────────────────────────────
function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Executes a script block with exponential backoff retry logic.
    .PARAMETER ScriptBlock
        The script block to execute.
    .PARAMETER MaxRetries
        Maximum number of retry attempts (default 3).
    .PARAMETER BaseDelaySeconds
        Base delay in seconds before first retry; doubles each attempt (default 2).
    .PARAMETER OperationName
        Friendly name for logging purposes.
    .EXAMPLE
        Invoke-WithRetry -ScriptBlock { DISM /Online /Cleanup-Image /ScanHealth } -OperationName "DISM ScanHealth"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [int]$MaxRetries = 3,

        [int]$BaseDelaySeconds = 2,

        [string]$OperationName = 'Operation'
    )

    $attempt = 0
    $lastError = $null

    while ($attempt -le $MaxRetries) {
        try {
            if ($attempt -gt 0) {
                Write-WinCareLog -Message "Retry $attempt/$MaxRetries for '$OperationName'..." -Severity Info
            }
            $result = & $ScriptBlock
            return $result
        }
        catch {
            $lastError = $_
            $attempt++
            if ($attempt -le $MaxRetries) {
                $delay = $BaseDelaySeconds * [math]::Pow(2, $attempt - 1)
                Write-WinCareLog -Message "'$OperationName' failed (attempt $attempt): $($_.Exception.Message). Retrying in ${delay}s..." -Severity Warning
                Start-Sleep -Seconds $delay
            }
        }
    }

    Write-WinCareLog -Message "'$OperationName' failed after $MaxRetries retries: $($lastError.Exception.Message)" -Severity Error
    throw $lastError
}

# ─────────────────────────────────────────────────────────────────────
# 9. Export-RegistryBackup
# ─────────────────────────────────────────────────────────────────────
function Export-RegistryBackup {
    <#
    .SYNOPSIS
        Exports a registry key to a .reg file for rollback purposes.
    .PARAMETER KeyPath
        The registry key path (e.g., 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion').
    .PARAMETER OutputPath
        File path for the exported .reg file.
    .PARAMETER Description
        Human-readable description of what this backup covers.
    .NOTES
        Citation: [MS Learn] reg export
        https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-export
    .EXAMPLE
        Export-RegistryBackup -KeyPath 'HKLM\SOFTWARE\Policies' -OutputPath '.\Backups\policies.reg' -Description 'Group Policy keys'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$KeyPath,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [string]$Description = ''
    )

    $dir = Split-Path $OutputPath -Parent
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    Write-WinCareLog -Message "Exporting registry backup: $KeyPath -> $OutputPath ($Description)" -Severity Info

    try {
        $regArgs = @('export', $KeyPath, $OutputPath, '/y')
        $proc = Start-Process -FilePath 'reg.exe' -ArgumentList $regArgs -NoNewWindow -Wait -PassThru
        if ($proc.ExitCode -ne 0) {
            throw "reg.exe export failed with exit code $($proc.ExitCode)"
        }
        Write-WinCareLog -Message "Registry backup saved: $OutputPath" -Severity Success
        return $OutputPath
    }
    catch {
        Write-WinCareLog -Message "Registry backup failed for '$KeyPath': $($_.Exception.Message)" -Severity Error
        throw
    }
}

# ─────────────────────────────────────────────────────────────────────
# 10. Get-PSVersionInfo
# ─────────────────────────────────────────────────────────────────────
function Get-PSVersionInfo {
    <#
    .SYNOPSIS
        Returns a structured summary of the current PowerShell environment.
    .OUTPUTS
        PSCustomObject with Version, Edition, OS, CLRVersion, and Is7Plus.
    .EXAMPLE
        Get-PSVersionInfo | Format-List
    #>
    [CmdletBinding()]
    param()

    [PSCustomObject]@{
        Version    = $PSVersionTable.PSVersion.ToString()
        Edition    = if ($PSVersionTable.PSEdition) { $PSVersionTable.PSEdition } else { 'Desktop' }
        OS         = if ($PSVersionTable.OS) { $PSVersionTable.OS } else { [System.Environment]::OSVersion.VersionString }
        CLRVersion = if ($PSVersionTable.CLRVersion) { $PSVersionTable.CLRVersion.ToString() } else { 'N/A (Core)' }
        Is7Plus    = $PSVersionTable.PSVersion.Major -ge 7
    }
}

# ─────────────────────────────────────────────────────────────────────
# Module exports
# ─────────────────────────────────────────────────────────────────────
Export-ModuleMember -Function @(
    'Write-WinCareLog'
    'Set-WinCareLogFile'
    'New-WinCareResult'
    'Get-WinCareConfig'
    'Save-WinCareFile'
    'Test-IsAdministrator'
    'Test-PendingReboot'
    'Get-SystemProfile'
    'Invoke-WithRetry'
    'Export-RegistryBackup'
    'Get-PSVersionInfo'
)
