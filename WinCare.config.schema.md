# WinCare Configuration Schema

This document describes every key in `WinCare.config.json` with types, defaults, and constraints.

---

## Top-Level Keys

| Key           | Type   | Required | Description                           |
|---------------|--------|----------|---------------------------------------|
| `version`     | string | Yes      | Semantic version of the config schema |
| `description` | string | No       | Human-readable config description     |
| `modules`     | object | Yes      | Per-module enable/disable and options  |
| `debloat`     | object | Yes      | Debloat target lists and exclusions   |
| `preferences` | object | Yes      | Global preferences and paths          |

---

## `modules` Object

Each module key is an object with at minimum an `enabled` (bool) property.

### `modules.repairHealth`

| Key                    | Type   | Default | Description                                       |
|------------------------|--------|---------|---------------------------------------------------|
| `enabled`              | bool   | `true`  | Whether to run this module                        |
| `runDISMScanHealth`    | bool   | `true`  | Run `DISM /ScanHealth` (read-only diagnostic)     |
| `runDISMRestoreHealth` | bool   | `false` | Run `DISM /RestoreHealth` (destructive — opt-in)  |
| `runSFC`               | bool   | `true`  | Run `sfc /scannow`                               |
| `runCheckDisk`         | bool   | `false` | Schedule `chkdsk` (destructive — opt-in)          |
| `checkDiskDrive`       | string | `"C:"`  | Target drive for chkdsk                           |

### `modules.windowsUpdate`

| Key                          | Type | Default | Description                              |
|------------------------------|------|---------|------------------------------------------|
| `enabled`                    | bool | `true`  | Whether to run this module               |
| `diagnosePending`            | bool | `true`  | Diagnose pending/stuck updates           |
| `resetComponents`            | bool | `false` | Reset WU components (destructive)        |
| `clearSoftwareDistribution`  | bool | `false` | Rename SoftwareDistribution (destructive)|

### `modules.securityScan`

| Key                   | Type | Default | Description                          |
|-----------------------|------|---------|--------------------------------------|
| `enabled`             | bool | `true`  | Whether to run this module           |
| `updateDefinitions`   | bool | `true`  | Update Defender definitions          |
| `runQuickScan`        | bool | `true`  | Run a quick scan                     |
| `runFullScan`         | bool | `false` | Run a full scan (long — opt-in)      |
| `checkDefenderStatus` | bool | `true`  | Report Defender configuration status |

### `modules.debloat`

| Key                          | Type   | Default       | Description                              |
|------------------------------|--------|---------------|------------------------------------------|
| `enabled`                    | bool   | `false`       | Whether to run this module (off by default)|
| `mode`                       | string | `"allowlist"` | `allowlist` or `blocklist`               |
| `removeProvisionedPackages`  | bool   | `false`       | Remove provisioned (all-user) packages   |
| `disableConsumerFeatures`    | bool   | `false`       | Disable consumer feature suggestions     |
| `categories`                 | object | all `false`   | Per-category enable flags                |

### `modules.appUpdates`

| Key                | Type     | Default | Description                            |
|--------------------|----------|---------|----------------------------------------|
| `enabled`          | bool     | `true`  | Whether to run this module             |
| `useWinGet`        | bool     | `true`  | Use WinGet for updates                 |
| `upgradeAll`       | bool     | `false` | Upgrade all packages (destructive)     |
| `approvedPackages` | string[] | `[]`    | Specific package IDs to upgrade        |

### `modules.driverGuidance`

| Key               | Type | Default | Description                              |
|-------------------|------|---------|------------------------------------------|
| `enabled`         | bool | `true`  | Whether to run this module               |
| `reportOnly`      | bool | `true`  | Only report — never auto-install         |
| `checkForMissing` | bool | `true`  | Check for devices without drivers        |
| `checkForOutdated`| bool | `true`  | Check for outdated driver versions       |
| `autoInstall`     | bool | `false` | Auto-install via Windows Update (unsafe) |

### `modules.gamingOptimize`

| Key                        | Type | Default | Description                              |
|----------------------------|------|---------|------------------------------------------|
| `enabled`                  | bool | `false` | Whether to run this module (off by default)|
| `enableGameMode`           | bool | `true`  | Enable Windows Game Mode                 |
| `setHighPerformancePower`  | bool | `false` | Switch to High Performance power plan    |
| `enableHAGS`               | bool | `false` | Enable Hardware-Accelerated GPU Scheduling|
| `disableStartupItems`      | bool | `false` | Disable non-essential startup items      |
| `optimizeNetworkSettings`  | bool | `false` | Apply Nagle/TCP optimizations            |
| `applyRegistryTweaks`      | bool | `false` | Apply gaming-related registry tweaks     |

---

## `debloat` Object

| Key                    | Type     | Description                                                    |
|------------------------|----------|----------------------------------------------------------------|
| `hardcodedExclusions`  | string[] | **Protected packages — enforced at runtime regardless of edits** |
| `additionalExclusions` | string[] | User-defined packages to never remove                          |
| `removalTargets`       | object   | Per-category lists of packages to remove                       |

### Hardcoded Exclusions (Non-Negotiable)

These 9 patterns are **always** protected. Even if removed from the config, the code enforces them:

1. `Microsoft.WindowsStore`
2. `Microsoft.WindowsCalculator`
3. `Microsoft.WindowsTerminal`
4. `Microsoft.DesktopAppInstaller`
5. `Microsoft.SecHealthUI`
6. `Microsoft.WindowsSecurity`
7. `Microsoft.UI.Xaml.*`
8. `Microsoft.VCLibs.*`
9. `Microsoft.NET.*`

---

## `preferences` Object

| Key               | Type   | Default        | Description                                |
|-------------------|--------|----------------|--------------------------------------------|
| `createRestorePoint` | bool | `true`         | Create a system restore point before actions|
| `backupRegistry`  | bool   | `true`         | Backup registry keys before modifications  |
| `dryRun`          | bool   | `false`        | Simulate actions without making changes    |
| `verboseLogging`  | bool   | `false`        | Enable verbose log output                  |
| `logDirectory`    | string | `"./Logs"`     | Path for log files                         |
| `reportDirectory` | string | `"./Reports"`  | Path for report files                      |
| `backupDirectory` | string | `"./Backups"`  | Path for backup files                      |
| `maxLogAgeDays`   | int    | `30`           | Auto-clean logs older than N days          |
| `timeoutMinutes`  | object | (per-module)   | Timeout values per module                  |

### `preferences.timeoutMinutes`

| Module          | Default (min) |
|-----------------|---------------|
| `collector`     | 5             |
| `repairHealth`  | 30            |
| `windowsUpdate` | 15            |
| `securityScan`  | 60            |
| `debloat`       | 10            |
| `appUpdates`    | 20            |
| `driverGuidance`| 5             |
| `gamingOptimize`| 5             |

---

## Safety Invariants

1. All destructive options default to `false`
2. Diagnostic-only options default to `true`
3. `debloat` and `gamingOptimize` modules default to `enabled: false`
4. Hardcoded exclusions are enforced in code regardless of config
5. `driverGuidance.autoInstall` should remain `false` — drivers from unofficial sources are never allowed
