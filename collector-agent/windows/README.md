# AI SOC Windows Collector

## Install (Admin PowerShell)

```powershell
cd C:\ai-soc-windows-collector
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install.ps1
```

If running from repo path first:

```powershell
cd "\\wsl$\Ubuntu\home\snp2315\Projects\CyberSecurity\ai-soc-platform\collector-agent\windows"
.\install.ps1
```

Installer copies files to `C:\ai-soc-windows-collector`, creates/updates `config.json`, installs service with automatic startup, configures service recovery (restart after 1 minute on first/second failure), and starts service.

## Modes

```powershell
.\install.ps1 -Repair
.\install.ps1 -Status
.\install.ps1 -Test
```

`-Status` prints:
- service installed/running/stopped
- config exists
- backend reachable

`-Test` sends synthetic test event:
- `event_type = windows_collector_test`
- `source = configured source_name`
- `severity = low`

## Service Commands

```powershell
Get-Service AISOCWindowsCollector
Restart-Service AISOCWindowsCollector
Stop-Service AISOCWindowsCollector
Start-Service AISOCWindowsCollector
```

Collector logs:

```text
C:\ai-soc-windows-collector\logs\collector.log
```

## Uninstall

Stop and remove service manually if needed:

```powershell
py -3 windows_service.py stop
py -3 windows_service.py remove
```

## Reboot Verification

1. Reboot Windows.
2. After login, run:

```powershell
Get-Service AISOCWindowsCollector
```

Expected: `Status = Running`, `StartType = Automatic`.

## Troubleshooting

- `config.json missing required fields`: run `.\install.ps1 -Repair` and provide `backend_url`, `collector_token`, `source_name`.
- `backend reachable: no`: verify backend URL and `http://<backend>/health/ready`.
- `test event rejected`: token invalid/disabled, or backend ingest unavailable.
