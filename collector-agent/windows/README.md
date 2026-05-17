# AI SOC Windows Failed-Login Collector

Native Windows collector for Security Event ID `4625`, "An account failed to log on."

It runs directly in Windows PowerShell, reads the local Windows Security log, stores the last processed `record_id` in `state.json`, and sends failed-login events to the Dockerized backend at `/collector/ingest`.

## Test Steps

Step A: Run backend/frontend from the project root:

```bash
cd /home/snp2315/Projects/CyberSecurity/ai-soc-platform
cp .env.example .env
docker compose up --build
```

Step B: On Windows, open PowerShell as Administrator.

Step C: Install collector dependencies:

```powershell
cd "\\wsl$\Ubuntu\home\snp2315\Projects\CyberSecurity\ai-soc-platform\collector-agent\windows"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Step D: Create config:

```powershell
copy config.example.json config.json
```

Edit `config.json` if your backend is not reachable at `http://localhost:8000`.

Step E: Run collector:

```powershell
python windows_event_collector.py
```

Or:

```powershell
.\run.ps1
```

Step F: Generate test event:

Lock Windows with `Win + L` and intentionally enter a wrong password 3 times.

Step G: Open:

```text
http://localhost:3000
http://localhost:8000/docs
```

Step H: Verify the failed-login alert appears in the Alerts page. Look for `Windows Failed Login Detected`, host, username, source IP, severity, count, and timestamp.

## Event Viewer Verification

Open:

```text
eventvwr.msc -> Windows Logs -> Security -> Event ID 4625
```

The collector reads the same Security log records and sends the parsed fields to AI SOC. The local state format is shown in `state.json.example`; the active state file is `state.json`.

## Configuration

```json
{
  "backend_url": "http://localhost:8000",
  "api_token": "test-collector-token",
  "poll_interval_seconds": 5,
  "log_name": "Security",
  "event_ids": [4625],
  "state_file": "state.json"
}
```

The API token must exist in backend `COLLECTOR_API_KEYS`, for example:

```text
COLLECTOR_API_KEYS=test-collector-token:6a016ae4ffb4489b3a44ba89
```

The user viewing the dashboard must belong to the same organization ID. The development Docker Compose setup creates that organization at startup.

## Troubleshooting

Use Administrator PowerShell. Reading the Security log generally requires elevated privileges.

If no alerts appear:

```powershell
Get-Content .\state.json
python windows_event_collector.py
```

Check backend logs:

```powershell
docker compose logs -f backend
```
