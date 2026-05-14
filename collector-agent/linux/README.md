# AI SOC Linux Collector

Linux endpoint collector for the AI SOC platform. It reads local telemetry only and sends normalized events to `POST /collector/ingest` with `X-Collector-Token`.

## What It Collects

- SSH/auth logs from `/var/log/auth.log` and `/var/log/secure`
- Sudo command and sudo failure log lines
- Read-only process listings from `ps`
- Read-only Docker container listings and inspect output when Docker is available
- SHA-256 file integrity hashes for configured sensitive paths
- Endpoint heartbeat events

The collector does not read or print sensitive file contents. File integrity monitoring hashes files only.

## Installation

Create a Linux collector in the AI SOC dashboard first and copy the one-time token.

```bash
cd collector-agent/linux
bash install.sh
```

The installer:

- Checks `python3`
- Creates `.venv`
- Installs `requirements.txt`
- Prompts for backend URL, collector token, and source name
- Writes `config.json`
- Creates `ai-soc-linux-collector.service`
- Enables and starts the systemd service

Run as root or with sudo for full `/var/log/auth.log`, `/var/log/secure`, `/etc/shadow`, Docker, and systemd access. The collector can run without root, but permission-restricted inputs will be skipped and logged.

## Manual Configuration

```bash
cd collector-agent/linux
cp config.example.json config.json
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

Edit `config.json`:

- `backend_url`: backend base URL or full `/collector/ingest` URL
- `collector_token`: one-time collector token from AI SOC
- `source_name`: endpoint/source name shown in logs
- `polling_interval_seconds`: collection loop interval
- `batch_size`: maximum events per send
- `logs_directory`: where `collector.log` is written
- `state_file`: file offset, Docker, process, heartbeat, and hash state
- `auth_log_paths`: auth log files to tail
- `watched_files`: files to hash for integrity monitoring
- `enable_process_monitoring`: enable read-only `ps`
- `enable_docker_monitoring`: enable read-only Docker checks
- `enable_file_integrity`: enable watched file hashing
- `heartbeat_interval_seconds`: heartbeat cadence

## Test Mode

Sends one synthetic heartbeat event and exits:

```bash
cd collector-agent/linux
python3 linux_collector.py --test
```

Expected result:

- Command exits `0`
- `logs/collector.log` shows a successful send
- Dashboard Logs page shows `linux_endpoint_heartbeat`
- Collector `last_seen_at` updates

## Once Mode

Collects one batch, sends it, saves state only after successful delivery, and exits:

```bash
cd collector-agent/linux
python3 linux_collector.py --once
```

Continuous mode is the default:

```bash
python3 linux_collector.py
```

## Systemd

```bash
sudo systemctl status ai-soc-linux-collector --no-pager
sudo systemctl restart ai-soc-linux-collector
sudo journalctl -u ai-soc-linux-collector -f
```

Uninstall:

```bash
cd collector-agent/linux
bash uninstall.sh
```

## Safe Test Commands

These commands generate normal administrative telemetry without offensive behavior:

```bash
logger -p authpriv.notice "sshd[1001]: Failed password for invalid user testuser from 127.0.0.1 port 2222 ssh2"
logger -p authpriv.notice "sshd[1002]: Accepted publickey for $USER from 127.0.0.1 port 2222 ssh2"
sudo -l
python3 linux_collector.py --once
```

For file integrity testing, add a harmless temporary file to `watched_files`, run `--once` once to baseline it, edit the temp file, then run `--once` again.

## Dashboard Verification

1. Create a collector with type `linux`.
2. Install this agent using the returned token.
3. Run `python3 linux_collector.py --test`.
4. Open Logs and filter for `linux_endpoint_heartbeat`.
5. Open Collectors and confirm `last_seen_at` changed.
6. Create an enabled detection rule, run a matching test, then check Alerts, Incidents, SOAR, and Realtime.

## Detection Rule Examples

Linux SSH Failed Login:

```json
{
  "name": "Linux SSH Failed Login",
  "description": "Detect failed SSH authentication from Linux collectors.",
  "severity": "high",
  "event_type": "linux_ssh_failed_login",
  "conditions": [
    {"field": "message", "operator": "contains", "value": "failed SSH login"}
  ],
  "mitre_tactic": "Credential Access",
  "mitre_technique": "T1110 - Brute Force",
  "enabled": true
}
```

Linux Sudo Failure:

```json
{
  "name": "Linux Sudo Failure",
  "description": "Detect failed sudo activity.",
  "severity": "high",
  "event_type": "linux_sudo_failure",
  "conditions": [
    {"field": "message", "operator": "contains", "value": "sudo failure"}
  ],
  "mitre_tactic": "Privilege Escalation",
  "mitre_technique": "T1548 - Abuse Elevation Control Mechanism",
  "enabled": true
}
```

Linux File Integrity Change:

```json
{
  "name": "Linux File Integrity Change",
  "description": "Detect changes to watched Linux system files.",
  "severity": "critical",
  "event_type": "linux_file_integrity_change",
  "conditions": [
    {"field": "message", "operator": "contains", "value": "file integrity change"}
  ],
  "mitre_tactic": "Defense Evasion",
  "mitre_technique": "T1562 - Impair Defenses",
  "enabled": true
}
```

Privileged Docker Container:

```json
{
  "name": "Privileged Docker Container",
  "description": "Detect privileged containers or sensitive host filesystem mounts.",
  "severity": "critical",
  "event_type": "linux_docker_privileged_container",
  "conditions": [
    {"field": "message", "operator": "contains", "value": "Docker"}
  ],
  "mitre_tactic": "Privilege Escalation",
  "mitre_technique": "T1611 - Escape to Host",
  "enabled": true
}
```

Syslog Critical Event:

```json
{
  "name": "Syslog Critical Event",
  "description": "Alert on critical syslog messages.",
  "severity": "critical",
  "event_type": "syslog_event",
  "conditions": [
    {"field": "message", "operator": "contains", "value": "critical event"}
  ],
  "mitre_tactic": "Impact",
  "mitre_technique": "Unknown",
  "enabled": true
}
```

## Troubleshooting

- `401 Invalid collector token`: create a new collector and update `collector_token`.
- `403 Collector is disabled`: enable the collector in the dashboard.
- No auth events: run with sudo/root or check `auth_log_paths`.
- No Docker events: Docker may be absent, stopped, or inaccessible to the service user.
- No file integrity events: first run creates baselines; changes are detected on later runs.
- Duplicate prevention: log offsets and hashes are stored in `state.json`; delete it only when you intentionally want to rebuild baselines.
- Backend unreachable: verify `backend_url`, firewall rules, and `curl http://127.0.0.1/health/ready`.
