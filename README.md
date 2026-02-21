## About

WinCare was developed because my twin brother and I have a habit of experimenting with Windows the way some people tinker with cars: poke it, tune it, “optimize” it, and occasionally (often) break something important. When you’re breaking and fixing the same PC multiple times a week, you either stop touching things… or you build a repeatable way to undo your own chaos.

So we built WinCare to help us recover from the stuff we kept accidentally (and sometimes intentionally) messing up. It collects a clean snapshot of what’s going on, figures out the most likely culprits, and then runs careful, configurable fixes with reporting and rollback artifacts where it can.

It’s not magic, and it won’t replace good judgment—but for normal Windows users and fellow tinkerers, it should be able to handle most of the common “what did I just do to my PC?” problems automatically, and adapt to different machines over time.

---

## Overview

WinCare is a safety-first PowerShell utility for Windows system intake, analysis, and controlled remediation. It emphasizes conservative defaults, explicit opt-in for riskier operations, and structured reporting so you can understand what was found, what was changed, and how to roll back where applicable.

---

## What WinCare Does

* Collects system intake data without mutating system state (`Collector.ps1`).
* Analyzes intake and generates a tailored remediation plan (`Analyze-Intake.ps1`).
* Executes modular, reversible maintenance and remediation actions via `WinCare.ps1`.
* Produces structured reports, including rollback artifact references and next-step guidance.

---

## What WinCare Does Not Do

* Does not auto-elevate privileges.
* Does not uninstall load-bearing Windows components (Defender, Windows Update chain, .NET, VC++ runtimes, Microsoft Store frameworks).
* Does not use `Win32_Product` for software inventory.
* Does not delete Windows Update caches (`SoftwareDistribution` and `catroot2` are rename-only when enabled).
* Does not run live `chkdsk /f` in-session.

---

## Prerequisites

* Windows PowerShell 5.1 or later.
* An Administrator PowerShell session for modules that require elevated operations.
* Pester 5.6.1 for the test suite.
* Optional: WinGet for `AppUpdates` module behavior.

---

## Quick Start

```powershell
# 1) Collect intake
.\Collector.ps1 -OutputDir .\Reports

# 2) Analyze intake and generate tailored config + plan
.\Analyze-Intake.ps1 -IntakePath .\Reports\WinCare_Intake_<timestamp>.json

# 3) Run orchestrator safely first
.\WinCare.ps1 -ConfigPath .\WinCare.config.json -DryRun -AuditOnly
```

---

## Usage

```powershell
# Dry-run full orchestration (no intentional mutations)
.\WinCare.ps1 -ConfigPath .\WinCare.config.json -DryRun

# Audit-only execution (preflight + reporting flow)
.\WinCare.ps1 -ConfigPath .\WinCare.config.json -DryRun -AuditOnly

# Run specific modules only (after preflight)
.\WinCare.ps1 -ConfigPath .\WinCare.config.json -ModulesOnly RepairHealth,WindowsUpdate -DryRun
```

---

## Module Risk Levels

WinCare assigns modules a practical risk level based on the likelihood and impact of system changes.

* **Low:** `DriverGuidance`, `Reporting`
* **Medium:** `SecurityScan`, `AppUpdates`, Windows Update diagnostics
* **Elevated (when enabled):** `RepairHealth` restore path, `Debloat`, `GamingOptimize`, Windows Update reset path

Elevated-risk operations are **disabled by default** and must be explicitly enabled in the configuration.

---

## Rollback and Recovery

* Registry backups are exported to the configured backup directory when relevant modules modify registry state.
* Debloat writes a manifest under the reports directory for package-level rollback guidance.
* Reporting aggregates rollback artifacts and recommended next steps into JSON/TXT summaries.

If a module reports `Failed` or `PartialSuccess`, review the generated report artifacts before retrying or enabling additional actions.

---

## FAQ

### Why does WinCare skip actions?

Modules are configuration-gated, and many operations are intentionally disabled by default to reduce risk. Skips are expected until you explicitly enable the actions you want.

### Why run `-DryRun` first?

`-DryRun` validates the workflow, configuration, and reporting without applying intentional mutations. This is the recommended first step before enabling any elevated-risk actions.

### Why does `AppUpdates` sometimes skip?

`AppUpdates` will skip when the module is disabled, `useWinGet` is set to false, or WinGet is not available on the system.

---

## Safety Guarantees

* Conservative defaults with explicit toggles for higher-risk operations.
* Structured result objects for every module execution.
* No silent failure suppression; failures are surfaced in module output and reports.
* Reports include issues found, issues remaining, rollback artifacts, and next-step guidance.

---

## References

This project follows a citation-first approach across module logic and planning (Microsoft Learn first, then vendor documentation, and community references when appropriate).

* DISM image servicing: [https://learn.microsoft.com/windows-hardware/manufacture/desktop/repair-a-windows-image](https://learn.microsoft.com/windows-hardware/manufacture/desktop/repair-a-windows-image)
* SFC usage: [https://learn.microsoft.com/windows-server/administration/windows-commands/sfc](https://learn.microsoft.com/windows-server/administration/windows-commands/sfc)
* Windows Update troubleshooting: [https://learn.microsoft.com/troubleshoot/windows-client/installing-updates-features-roles/troubleshoot-windows-update-issues](https://learn.microsoft.com/troubleshoot/windows-client/installing-updates-features-roles/troubleshoot-windows-update-issues)
* Defender management: [https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows](https://learn.microsoft.com/defender-endpoint/microsoft-defender-antivirus-windows)
* WinGet documentation: [https://learn.microsoft.com/windows/package-manager/winget/](https://learn.microsoft.com/windows/package-manager/winget/)

---

