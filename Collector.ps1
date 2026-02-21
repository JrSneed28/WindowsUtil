<#
.SYNOPSIS
    WinCare Phase 0 - Read-only system intake collector.

.DESCRIPTION
    Gathers a comprehensive, non-invasive snapshot of the current Windows system
    state. Outputs three files (JSON intake, plain-text summary, log) to the
    specified output directory.

    This script NEVER modifies the system. It collects only non-sensitive,
    system-level diagnostic data.

    Sections collected:
      A - OS & Hardware Identity
      B - Health & Integrity Status
      C - Software & Bloat Inventory
      D - Security & Defender Posture
      E - Network & Connectivity Baseline

.PARAMETER OutputDir
    Directory where output files are written. Defaults to .\Reports.

.PARAMETER TimeoutSeconds
    Maximum runtime in seconds. Defaults to 300 (5 minutes).

.EXAMPLE
    .\Collector.ps1
    .\Collector.ps1 -OutputDir C:\WinCare\Reports -TimeoutSeconds 600

.NOTES
    Author : WinCare Project
    Phase  : 0 (Read-Only Intake)
    Safety : No system modifications. No sensitive data collected.
    Citation: [MS Learn] Get-ComputerInfo, Get-CimInstance, DISM /Online
#>
[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDir = (Join-Path $PSScriptRoot 'Reports'),

    [Parameter()]
    [int]$TimeoutSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

#region -- Bootstrap ----------------------------------------------------------
$script:StartTime     = Get-Date
$script:IsAdmin       = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$script:CollectorVersion = '1.0.0'

# Ensure output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$timestamp  = $script:StartTime.ToString('yyyyMMdd_HHmmss')
$jsonPath   = Join-Path $OutputDir "WinCare_Intake_$timestamp.json"
$summaryPath = Join-Path $OutputDir "WinCare_Intake_$timestamp.txt"
$logPath    = Join-Path $OutputDir "WinCare_Collector_$timestamp.log"

# Simple logger (no dependency on WinCareUtils for Phase 0 portability)
function Write-CollectorLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR')][string]$Level = 'INFO'
    )
    $ts  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$ts] [$Level] $Message"
    Add-Content -Path $logPath -Value $line -Encoding UTF8
    switch ($Level) {
        'INFO'  { Write-Information $line -InformationAction Continue }
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Error $Message }
    }
}

# Timeout guard
$script:Deadline = $script:StartTime.AddSeconds($TimeoutSeconds)
function Test-Timeout {
    if ((Get-Date) -ge $script:Deadline) {
        Write-CollectorLog "Timeout reached ($TimeoutSeconds seconds). Finalizing with partial data." -Level WARN
        return $true
    }
    return $false
}

# Safe command runner - captures errors gracefully
function Invoke-SafeCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [switch]$RequiresAdmin
    )
    if ($RequiresAdmin -and -not $script:IsAdmin) {
        Write-CollectorLog "$Label - skipped (requires elevation)" -Level WARN
        return @{ Status = 'Skipped'; Reason = 'Requires administrator privileges'; Data = $null }
    }
    if (Test-Timeout) {
        Write-CollectorLog "$Label - skipped (timeout)" -Level WARN
        return @{ Status = 'Skipped'; Reason = 'Timeout reached'; Data = $null }
    }
    try {
        Write-CollectorLog "Collecting: $Label"
        $data = & $ScriptBlock
        return @{ Status = 'OK'; Reason = $null; Data = $data }
    }
    catch {
        Write-CollectorLog "$Label - ERROR: $($_.Exception.Message)" -Level ERROR
        return @{ Status = 'Error'; Reason = $_.Exception.Message; Data = $null }
    }
}
#endregion

Write-CollectorLog "=== WinCare Collector v$($script:CollectorVersion) ==="
Write-CollectorLog "Run as Administrator: $($script:IsAdmin)"
Write-CollectorLog "Output directory: $OutputDir"
Write-CollectorLog "Timeout: $TimeoutSeconds seconds"

#region -- Section A: OS & Hardware Identity ----------------------------------
Write-CollectorLog "--- Section A: OS & Hardware Identity ---"

$sectionA = [ordered]@{}

# A1 - OS version & edition
$a1 = Invoke-SafeCommand -Label 'OS Version & Edition' -ScriptBlock {
    $os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, SystemDirectory
    $ver = [System.Environment]::OSVersion.Version
    [ordered]@{
        Caption       = $os.Caption
        Version       = $os.Version
        Build         = $os.BuildNumber
        Architecture  = $os.OSArchitecture
        InstallDate   = $os.InstallDate
        LastBoot      = $os.LastBootUpTime
        MajorVersion  = $ver.Major
        MinorVersion  = $ver.Minor
        IsWindows11   = ($os.BuildNumber -ge 22000)
    }
}
$sectionA['OSVersion'] = $a1

# A2 - Edition details (Home/Pro/Enterprise/LTSC)
$a2 = Invoke-SafeCommand -Label 'Edition Details' -ScriptBlock {
    $edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).EditionID
    $productName = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).ProductName
    $displayVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).DisplayVersion
    $ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).UBR
    [ordered]@{
        EditionID      = $edition
        ProductName    = $productName
        DisplayVersion = $displayVersion
        UBR            = $ubr
        IsHome         = ($edition -like '*Home*' -or $edition -like '*Core*')
        IsLTSC         = ($edition -like '*LTSC*' -or $edition -like '*EnterpriseS*')
    }
}
$sectionA['Edition'] = $a2

# A3 - Hardware summary
$a3 = Invoke-SafeCommand -Label 'Hardware Summary' -ScriptBlock {
    $cs = Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory, NumberOfProcessors, NumberOfLogicalProcessors, SystemType, PCSystemType
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1 Name, MaxClockSpeed, NumberOfCores, NumberOfLogicalProcessors, Architecture
    $bios = Get-CimInstance Win32_BIOS | Select-Object SMBIOSBIOSVersion, Manufacturer, ReleaseDate
    $isLaptop = ($cs.PCSystemType -eq 2)
    $isARM64 = ($cpu.Architecture -eq 12 -or $cs.SystemType -like '*ARM*')
    $isVM = ($cs.Model -like '*Virtual*' -or $cs.Model -like '*VMware*' -or $cs.Manufacturer -like '*Microsoft Corporation*' -and $cs.Model -like '*Virtual*')
    [ordered]@{
        Manufacturer = $cs.Manufacturer
        Model        = $cs.Model
        TotalRAM_GB  = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        CPU          = $cpu.Name
        CPUCores     = $cpu.NumberOfCores
        CPULogical   = $cpu.NumberOfLogicalProcessors
        IsLaptop     = $isLaptop
        IsARM64      = $isARM64
        IsVM         = $isVM
        BIOS         = $bios.SMBIOSBIOSVersion
    }
}
$sectionA['Hardware'] = $a3

# A4 - Disk space
$a4 = Invoke-SafeCommand -Label 'Disk Space' -ScriptBlock {
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
        [ordered]@{
            Drive      = $_.DeviceID
            Size_GB    = [math]::Round($_.Size / 1GB, 2)
            Free_GB    = [math]::Round($_.FreeSpace / 1GB, 2)
            UsedPct    = if ($_.Size -gt 0) { [math]::Round((1 - $_.FreeSpace / $_.Size) * 100, 1) } else { 0 }
            LowSpace   = ($_.FreeSpace -lt 10GB)
        }
    }
}
$sectionA['DiskSpace'] = $a4

# A5 - Domain/Entra/Workgroup
$a5 = Invoke-SafeCommand -Label 'Domain & Enrollment' -ScriptBlock {
    $cs = Get-CimInstance Win32_ComputerSystem | Select-Object Domain, PartOfDomain, DomainRole
    $dsregOutput = try { dsregcmd /status 2>&1 | Out-String } catch { '' }
    $isEntraJoined = $dsregOutput -match 'AzureAdJoined\s*:\s*YES'
    $isIntuneManaged = $dsregOutput -match 'MDMUrl\s*:\s*https'
    [ordered]@{
        Domain         = $cs.Domain
        IsDomainJoined = $cs.PartOfDomain
        DomainRole     = $cs.DomainRole
        IsEntraJoined  = [bool]$isEntraJoined
        IsIntuneManaged = [bool]$isIntuneManaged
    }
}
$sectionA['DomainEnrollment'] = $a5

# A6 - PowerShell info
$a6 = Invoke-SafeCommand -Label 'PowerShell Info' -ScriptBlock {
    [ordered]@{
        PSVersion = $PSVersionTable.PSVersion.ToString()
        PSEdition = $PSVersionTable.PSEdition
        CLRVersion = if ($PSVersionTable.CLRVersion) { $PSVersionTable.CLRVersion.ToString() } else { 'N/A' }
        Is7Plus   = ($PSVersionTable.PSVersion.Major -ge 7)
    }
}
$sectionA['PowerShell'] = $a6
#endregion

#region -- Section B: Health & Integrity Status -------------------------------
Write-CollectorLog "--- Section B: Health & Integrity Status ---"

$sectionB = [ordered]@{}

# B1 - DISM component store health (read-only check)
$b1 = Invoke-SafeCommand -Label 'DISM Health Check' -RequiresAdmin -ScriptBlock {
    $dismOutput = & dism.exe /Online /Cleanup-Image /CheckHealth 2>&1 | Out-String
    [ordered]@{
        RawOutput  = $dismOutput.Trim()
        IsHealthy  = ($dismOutput -match 'No component store corruption detected' -or $dismOutput -match 'The component store is repairable')
        NeedsRepair = ($dismOutput -match 'The component store is repairable')
    }
}
$sectionB['DISM'] = $b1

# B2 - SFC last result (from CBS log, read-only)
$b2 = Invoke-SafeCommand -Label 'SFC Last Result' -ScriptBlock {
    $cbsLog = Join-Path $env:SystemRoot 'Logs\CBS\CBS.log'
    $sfcResult = 'Unknown'
    if (Test-Path $cbsLog) {
        # Read last 500 lines for SFC results
        $lastLines = Get-Content $cbsLog -Tail 500 -ErrorAction SilentlyContinue
        if ($lastLines -match 'Verification 100% complete') {
            if ($lastLines -match 'found corrupt files and successfully repaired') {
                $sfcResult = 'Repaired'
            }
            elseif ($lastLines -match 'did not find any integrity violations') {
                $sfcResult = 'Clean'
            }
            elseif ($lastLines -match 'found corrupt files but was unable to fix') {
                $sfcResult = 'CorruptUnfixed'
            }
        }
    }
    [ordered]@{
        LastSFCResult = $sfcResult
        CBSLogExists  = (Test-Path $cbsLog)
    }
}
$sectionB['SFC'] = $b2

# B3 - Pending reboot detection
$b3 = Invoke-SafeCommand -Label 'Pending Reboot Check' -ScriptBlock {
    $checks = [ordered]@{
        ComponentBasedServicing = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
        WindowsUpdate          = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')
        PendingFileRename      = [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
        JoinDomain             = (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\JoinDomain')
    }
    $checks['AnyPending'] = ($checks.Values -contains $true)
    $checks
}
$sectionB['PendingReboot'] = $b3

# B4 - Event log error summary (last 7 days, top errors)
$b4 = Invoke-SafeCommand -Label 'Event Log Error Summary' -ScriptBlock {
    $since = (Get-Date).AddDays(-7)
    $sysErrors = @()
    try {
        $sysErrors = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            Level = 2  # Error
            StartTime = $since
        } -MaxEvents 50 -ErrorAction SilentlyContinue |
        Group-Object { $_.ProviderName } |
        Sort-Object Count -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            [ordered]@{
                Source = $_.Name
                Count  = $_.Count
                Sample = ($_.Group | Select-Object -First 1).Message
            }
        }
    } catch {}
    $appErrors = @()
    try {
        $appErrors = Get-WinEvent -FilterHashtable @{
            LogName = 'Application'
            Level = 2
            StartTime = $since
        } -MaxEvents 50 -ErrorAction SilentlyContinue |
        Group-Object { $_.ProviderName } |
        Sort-Object Count -Descending |
        Select-Object -First 10 |
        ForEach-Object {
            [ordered]@{
                Source = $_.Name
                Count  = $_.Count
                Sample = ($_.Group | Select-Object -First 1).Message
            }
        }
    } catch {}
    [ordered]@{
        SystemErrorSources      = $sysErrors
        ApplicationErrorSources = $appErrors
    }
}
$sectionB['EventLogSummary'] = $b4

# B5 - Disk health (SMART basic via CIM)
$b5 = Invoke-SafeCommand -Label 'Disk Health' -ScriptBlock {
    $disks = Get-CimInstance -Namespace 'root\wmi' -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction SilentlyContinue
    if ($disks) {
        $disks | ForEach-Object {
            [ordered]@{
                InstanceName = $_.InstanceName
                PredictFailure = $_.PredictFailure
                Reason = $_.Reason
            }
        }
    }
    else {
        [ordered]@{ Status = 'SMART data not available via WMI' }
    }
}
$sectionB['DiskHealth'] = $b5
#endregion

#region -- Section C: Software & Bloat Inventory ------------------------------
Write-CollectorLog "--- Section C: Software & Bloat Inventory ---"

$sectionC = [ordered]@{}

# C1 - Installed AppX packages (NOT Win32_Product - that triggers MSI reconfiguration)
$c1 = Invoke-SafeCommand -Label 'AppX Packages' -ScriptBlock {
    Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
    Where-Object { $_.IsFramework -eq $false } |
    Select-Object Name, PackageFullName, Version, Publisher, NonRemovable, SignatureKind |
    ForEach-Object {
        [ordered]@{
            Name         = $_.Name
            FullName     = $_.PackageFullName
            Version      = $_.Version
            Publisher    = $_.Publisher
            NonRemovable = $_.NonRemovable
            SignatureKind = $_.SignatureKind.ToString()
        }
    }
}
$sectionC['AppXPackages'] = $c1

# C2 - Installed programs (registry-based, safe - NO Win32_Product)
$c2 = Invoke-SafeCommand -Label 'Installed Programs (Registry)' -ScriptBlock {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $programs = $paths | ForEach-Object {
        Get-ItemProperty $_ -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
    } | Sort-Object DisplayName -Unique
    $programs | ForEach-Object {
        [ordered]@{
            Name      = $_.DisplayName
            Version   = $_.DisplayVersion
            Publisher = $_.Publisher
            InstallDate = $_.InstallDate
        }
    }
}
$sectionC['InstalledPrograms'] = $c2

# C3 - Startup items
$c3 = Invoke-SafeCommand -Label 'Startup Items' -ScriptBlock {
    $startupItems = @()
    # Registry Run keys
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
            $props.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSProvider','PSDrive') } | ForEach-Object {
                $startupItems += [ordered]@{
                    Source  = $key
                    Name    = $_.Name
                    Command = $_.Value
                    Type    = 'Registry'
                }
            }
        }
    }
    # Scheduled tasks at logon
    try {
        Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.Triggers | Where-Object { $_ -is [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.CimTrigger] } } |
        Select-Object -First 20 TaskName, TaskPath, State |
        ForEach-Object {
            $startupItems += [ordered]@{
                Source  = $_.TaskPath
                Name    = $_.TaskName
                Command = ''
                Type    = 'ScheduledTask'
                State   = $_.State.ToString()
            }
        }
    } catch {}
    $startupItems
}
$sectionC['StartupItems'] = $c3

# C4 - WinGet availability
$c4 = Invoke-SafeCommand -Label 'WinGet Availability' -ScriptBlock {
    $wingetPath = Get-Command winget -ErrorAction SilentlyContinue
    if ($wingetPath) {
        $ver = (winget --version 2>&1) -replace '[^\d.]', ''
        [ordered]@{
            Available = $true
            Version   = $ver
            Path      = $wingetPath.Source
        }
    }
    else {
        [ordered]@{
            Available = $false
            Version   = $null
            Path      = $null
        }
    }
}
$sectionC['WinGet'] = $c4
#endregion

#region -- Section D: Security & Defender Posture -----------------------------
Write-CollectorLog "--- Section D: Security & Defender Posture ---"

$sectionD = [ordered]@{}

# D1 - Windows Defender status
$d1 = Invoke-SafeCommand -Label 'Defender Status' -ScriptBlock {
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mpStatus) {
        [ordered]@{
            AMServiceEnabled          = $mpStatus.AMServiceEnabled
            AntispywareEnabled        = $mpStatus.AntispywareEnabled
            AntivirusEnabled          = $mpStatus.AntivirusEnabled
            RealTimeProtectionEnabled = $mpStatus.RealTimeProtectionEnabled
            BehaviorMonitorEnabled    = $mpStatus.BehaviorMonitorEnabled
            IoavProtectionEnabled     = $mpStatus.IoavProtectionEnabled
            NISEnabled                = $mpStatus.NISEnabled
            OnAccessProtectionEnabled = $mpStatus.OnAccessProtectionEnabled
            SignatureVersion          = $mpStatus.AntivirusSignatureVersion
            SignatureLastUpdated      = $mpStatus.AntivirusSignatureLastUpdated
            FullScanAge               = $mpStatus.FullScanAge
            QuickScanAge              = $mpStatus.QuickScanAge
        }
    }
    else {
        [ordered]@{ Status = 'Defender status unavailable' }
    }
}
$sectionD['Defender'] = $d1

# D2 - Third-party AV detection
$d2 = Invoke-SafeCommand -Label 'Third-Party AV Detection' -ScriptBlock {
    $avProducts = @()
    try {
        $avProducts = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
        ForEach-Object {
            [ordered]@{
                DisplayName       = $_.displayName
                ProductState      = $_.productState
                PathToSignedProductExe = $_.pathToSignedProductExe
            }
        }
    } catch {}
    $hasThirdPartyAV = ($avProducts | Where-Object { $_.DisplayName -notlike '*Windows Defender*' -and $_.DisplayName -notlike '*Microsoft Defender*' }).Count -gt 0
    [ordered]@{
        Products       = $avProducts
        HasThirdPartyAV = $hasThirdPartyAV
    }
}
$sectionD['ThirdPartyAV'] = $d2

# D3 - Firewall status
$d3 = Invoke-SafeCommand -Label 'Firewall Status' -ScriptBlock {
    $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled
    if ($fw) {
        $fw | ForEach-Object {
            [ordered]@{
                Profile = $_.Name
                Enabled = $_.Enabled
            }
        }
    }
    else {
        [ordered]@{ Status = 'Firewall status unavailable' }
    }
}
$sectionD['Firewall'] = $d3

# D4 - UAC level
$d4 = Invoke-SafeCommand -Label 'UAC Level' -ScriptBlock {
    $uacKey = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    [ordered]@{
        EnableLUA                  = $uacKey.EnableLUA
        ConsentPromptBehaviorAdmin = $uacKey.ConsentPromptBehaviorAdmin
        PromptOnSecureDesktop      = $uacKey.PromptOnSecureDesktop
    }
}
$sectionD['UAC'] = $d4

# D5 - BitLocker (read-only check)
$d5 = Invoke-SafeCommand -Label 'BitLocker Status' -RequiresAdmin -ScriptBlock {
    $blv = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($blv) {
        $blv | ForEach-Object {
            [ordered]@{
                MountPoint       = $_.MountPoint
                ProtectionStatus = $_.ProtectionStatus.ToString()
                EncryptionMethod = $_.EncryptionMethod.ToString()
                VolumeStatus     = $_.VolumeStatus.ToString()
            }
        }
    }
    else {
        [ordered]@{ Status = 'BitLocker not available or not enabled' }
    }
}
$sectionD['BitLocker'] = $d5
#endregion

#region -- Section E: Network & Connectivity Baseline -------------------------
Write-CollectorLog "--- Section E: Network & Connectivity Baseline ---"

$sectionE = [ordered]@{}

# E1 - Network adapters
$e1 = Invoke-SafeCommand -Label 'Network Adapters' -ScriptBlock {
    Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.Status -eq 'Up' } |
    Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed |
    ForEach-Object {
        [ordered]@{
            Name        = $_.Name
            Description = $_.InterfaceDescription
            Status      = $_.Status
            LinkSpeed   = $_.LinkSpeed
        }
    }
}
$sectionE['Adapters'] = $e1

# E2 - IP configuration
$e2 = Invoke-SafeCommand -Label 'IP Configuration' -ScriptBlock {
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } |
    Select-Object InterfaceAlias, IPAddress, PrefixLength, PrefixOrigin |
    ForEach-Object {
        [ordered]@{
            Interface    = $_.InterfaceAlias
            IP           = $_.IPAddress
            PrefixLength = $_.PrefixLength
            Origin       = $_.PrefixOrigin.ToString()
        }
    }
}
$sectionE['IPConfig'] = $e2

# E3 - DNS configuration
$e3 = Invoke-SafeCommand -Label 'DNS Configuration' -ScriptBlock {
    Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.ServerAddresses.Count -gt 0 } |
    ForEach-Object {
        [ordered]@{
            Interface = $_.InterfaceAlias
            DNS       = $_.ServerAddresses -join ', '
        }
    }
}
$sectionE['DNS'] = $e3

# E4 - WSUS configuration check
$e4 = Invoke-SafeCommand -Label 'WSUS Configuration' -ScriptBlock {
    $wuKey = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
    $auKey = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
    [ordered]@{
        WSUSServer      = if ($wuKey) { $wuKey.WUServer } else { $null }
        IsWSUSManaged   = [bool]($wuKey.WUServer)
        UseWUServer     = if ($auKey) { $auKey.UseWUServer } else { $null }
        NoAutoUpdate    = if ($auKey) { $auKey.NoAutoUpdate } else { $null }
    }
}
$sectionE['WSUS'] = $e4
#endregion

#region -- Assemble & Export --------------------------------------------------
Write-CollectorLog "--- Assembling intake data ---"

$intake = [ordered]@{
    _metadata = [ordered]@{
        CollectorVersion = $script:CollectorVersion
        Timestamp        = $script:StartTime.ToString('o')
        ComputerName     = $env:COMPUTERNAME
        RunAsAdmin       = $script:IsAdmin
        TimeoutSeconds   = $TimeoutSeconds
        DurationSeconds  = [math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 2)
    }
    SectionA_OS_Hardware     = $sectionA
    SectionB_Health          = $sectionB
    SectionC_Software        = $sectionC
    SectionD_Security        = $sectionD
    SectionE_Network         = $sectionE
}

# Write JSON intake
$jsonContent = $intake | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($jsonPath, $jsonContent, [System.Text.UTF8Encoding]::new($true))
Write-CollectorLog "JSON intake saved: $jsonPath"

# Write plain-text summary
$summaryLines = @()
$summaryLines += "========================================="
$summaryLines += "  WinCare System Intake Summary"
$summaryLines += "  Generated: $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
$summaryLines += "  Computer:  $($env:COMPUTERNAME)"
$summaryLines += "  Admin:     $($script:IsAdmin)"
$summaryLines += "========================================="
$summaryLines += ""

# OS
$osData = if ($sectionA['OSVersion'].Status -eq 'OK') { $sectionA['OSVersion'].Data } else { $null }
$edData = if ($sectionA['Edition'].Status -eq 'OK') { $sectionA['Edition'].Data } else { $null }
$hwData = if ($sectionA['Hardware'].Status -eq 'OK') { $sectionA['Hardware'].Data } else { $null }
$summaryLines += "OS:      $(if ($osData) { $osData.Caption } else { 'N/A' })"
$summaryLines += "Build:   $(if ($osData) { $osData.Build } else { 'N/A' })"
$summaryLines += "Edition: $(if ($edData) { $edData.ProductName } else { 'N/A' })  ($(if ($edData) { $edData.DisplayVersion } else { 'N/A' }))"
$summaryLines += "CPU:     $(if ($hwData) { $hwData.CPU } else { 'N/A' })"
$summaryLines += "RAM:     $(if ($hwData) { "$($hwData.TotalRAM_GB) GB" } else { 'N/A' })"
$summaryLines += ""

# Health
$dismData = if ($sectionB['DISM'].Status -eq 'OK') { $sectionB['DISM'].Data } else { $null }
$rebootData = if ($sectionB['PendingReboot'].Status -eq 'OK') { $sectionB['PendingReboot'].Data } else { $null }
$summaryLines += "DISM Healthy:    $(if ($dismData) { $dismData.IsHealthy } else { 'Skipped/Error' })"
$summaryLines += "Pending Reboot:  $(if ($rebootData) { $rebootData.AnyPending } else { 'Unknown' })"
$summaryLines += ""

# Security
$defData = if ($sectionD['Defender'].Status -eq 'OK') { $sectionD['Defender'].Data } else { $null }
$avData  = if ($sectionD['ThirdPartyAV'].Status -eq 'OK') { $sectionD['ThirdPartyAV'].Data } else { $null }
$summaryLines += "Defender Active:   $(if ($defData) { $defData.RealTimeProtectionEnabled } else { 'Unknown' })"
$summaryLines += "Third-Party AV:    $(if ($avData) { $avData.HasThirdPartyAV } else { 'Unknown' })"
$summaryLines += ""

# Software counts
$appxData = if ($sectionC['AppXPackages'].Status -eq 'OK') { $sectionC['AppXPackages'].Data } else { @() }
$progData = if ($sectionC['InstalledPrograms'].Status -eq 'OK') { $sectionC['InstalledPrograms'].Data } else { @() }
$summaryLines += "AppX Packages:     $(if ($appxData) { @($appxData).Count } else { 0 })"
$summaryLines += "Installed Programs: $(if ($progData) { @($progData).Count } else { 0 })"
$summaryLines += ""

$duration = [math]::Round(((Get-Date) - $script:StartTime).TotalSeconds, 2)
$summaryLines += "Collection completed in $duration seconds."

$summaryText = $summaryLines -join "`r`n"
[System.IO.File]::WriteAllText($summaryPath, $summaryText, [System.Text.UTF8Encoding]::new($true))
Write-CollectorLog "Summary saved: $summaryPath"

Write-CollectorLog "=== Collection complete. Duration: $duration seconds ==="

# Output summary to console
Write-Information "" -InformationAction Continue
Write-Information $summaryText -InformationAction Continue
Write-Information "" -InformationAction Continue
Write-Information "Files generated:" -InformationAction Continue
Write-Information "  JSON:    $jsonPath" -InformationAction Continue
Write-Information "  Summary: $summaryPath" -InformationAction Continue
Write-Information "  Log:     $logPath" -InformationAction Continue
#endregion
