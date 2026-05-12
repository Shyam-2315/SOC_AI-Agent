# AI SOC Windows Collector

Windows Security Collector Agent for the AI SOC platform.

The agent runs on native Windows and sends Windows Event Log telemetry to:

```text
http://127.0.0.1/collector/ingest
```

It only reads Windows logs and sends telemetry. It does not run commands, modify the host, test exploits, persist beyond the optional Windows service, or perform destructive actions.

## Collected Events

Security log:

- `4625` -> `windows_failed_login`, `high`
- `4624` -> `windows_successful_login`, `low`
- `4688` -> `windows_process_execution`, `medium`
- `4720`, `4722`, `4728` -> `windows_account_change`, `high`

Optional channels:

- `Microsoft-Windows-PowerShell/Operational`
  - suspicious command patterns -> `windows_powershell_activity`, `high`
- `Microsoft-Windows-Windows Defender/Operational`
  - Defender threat events -> `windows_defender_threat`, `critical`

If an optional channel is unavailable, the agent logs a warning and continues.

## Requirements

- Windows 10/11 or Windows Server
- Python 3 installed on Windows
- Administrator PowerShell for service install and Security log access
- A collector token created from the AI SOC Collectors page
- Backend reachable from Windows at `http://127.0.0.1`

## Install

Open PowerShell as Administrator:

```powershell
cd C:\path\to\ai-soc-platform\backend\collector-agent\windows
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install.ps1
```

The installer:

1. Checks Python exists.
2. Installs `requests` and `pywin32`.
3. Prompts for backend URL, collector token, and source name.
4. Writes `config.json`.
5. Installs the `AISOCWindowsCollector` service with automatic startup.
6. Starts the service and prints service status.

Use `-NoService` to only write config and dependencies:

```powershell
.\install.ps1 -NoService
```

## Manual Configuration

If you do not use the installer:

```powershell
Copy-Item config.example.json config.json
notepad config.json
python -m pip install -r requirements.txt
```

`config.json` fields:

- `backend_url`: backend base URL or full `/collector/ingest` URL
- `collector_token`: one-time collector token from AI SOC
- `source_name`: host/source label shown in logs
- `polling_interval_seconds`: continuous polling interval
- `batch_size`: max logs per send
- `logs_directory`: where `collector.log` is written
- `state_file`: last processed EventRecordID state

## Test Mode

Sends one synthetic low-severity event and exits:

```powershell
python windows_collector.py --test
```

Expected result:

- Command exits successfully.
- `logs\collector.log` contains a successful send.
- AI SOC Logs page shows `windows_security_event`.

## One-Shot Mode

Collects new Windows events once, sends a batch, advances `state.json`, and exits:

```powershell
python windows_collector.py --once
```

Run from Administrator PowerShell for Security log access.

## Continuous Mode

Runs in the foreground:

```powershell
python windows_collector.py
```

Stop with `Ctrl+C`.

## Windows Service

Service name:

```text
AISOCWindowsCollector
```

Useful commands:

```powershell
Get-Service AISOCWindowsCollector
Start-Service AISOCWindowsCollector
Stop-Service AISOCWindowsCollector
Restart-Service AISOCWindowsCollector
```

Service install without the installer:

```powershell
python windows_service.py install --startup auto
python windows_service.py start
```

## Uninstall

Open PowerShell as Administrator:

```powershell
cd C:\path\to\ai-soc-platform\backend\collector-agent\windows
.\uninstall.ps1
```

The uninstaller stops and removes the service. It keeps `config.json`, `state.json`, and logs unless you choose cleanup.

## Safe Testing

Use only normal Windows activity:

- Lock and unlock the workstation to create successful login telemetry.
- Run `python windows_collector.py --test`.
- Use `--once` after normal local activity.
- Use Windows Defender history if your host already has benign Defender events.

Do not run credential attacks, exploit tools, destructive scripts, malware samples, or evasion tests.

## Verify In AI SOC

1. Start backend/frontend.
2. Create a collector in AI SOC and copy its one-time token.
3. Install this Windows collector with that token.
4. Run:

   ```powershell
   python windows_collector.py --test
   python windows_collector.py --once
   ```

5. Open AI SOC:
   - Logs page: Windows events should appear.
   - Alerts page: alerts appear when enabled detection rules match the Windows event schema.
   - Realtime page: alert events appear when a matching rule creates an alert.
   - Dashboard: alert/incident counts update after matching rules generate alerts.

## Detection Rule Examples

Create rules in AI SOC such as:

- Event type equals `windows_failed_login`
- Message contains `TargetUserName=`
- Severity equals `high`

For a quick alert test, create a rule that matches:

- Event type: `windows_security_event`
- Condition: `message contains AI SOC Windows Collector synthetic test event`
- Severity: `medium` or higher

Then run:

```powershell
python windows_collector.py --test
```

## Troubleshooting

Check collector logs:

```powershell
Get-Content .\logs\collector.log -Tail 100
```

Common issues:

- `Missing config.json`: copy `config.example.json` to `config.json` or rerun `install.ps1`.
- `401 Invalid collector token`: create a new collector in AI SOC and update `collector_token`.
- `Collector ingestion is not configured`: backend collector auth is not configured or the collector token is unknown.
- Security channel access denied: run as Administrator or run the Windows service.
- Optional channel unavailable: PowerShell or Defender operational channel may be disabled; the agent continues.
- Backend unavailable: verify the Windows host can open `http://127.0.0.1/health/ready`.
