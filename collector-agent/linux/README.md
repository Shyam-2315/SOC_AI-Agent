# AI SOC Linux Collector

## Install

```bash
cd collector-agent/linux
sudo bash install.sh
```

Installer deploys to `/opt/ai-soc-linux-collector`, creates/updates `config.json`, installs and enables `ai-soc-linux-collector.service`, and starts it.

## Modes

```bash
sudo bash install.sh --repair
sudo bash install.sh --status
sudo bash install.sh --test
sudo bash uninstall.sh
```

`--status` prints:
- service enabled
- service running
- config exists
- backend reachable
- last collector logs

`--test` sends synthetic test event:
- `event_type = linux_collector_test`
- `source = configured source_name`
- `severity = low`

## Service Commands

```bash
sudo systemctl status ai-soc-linux-collector --no-pager
sudo systemctl restart ai-soc-linux-collector
sudo systemctl stop ai-soc-linux-collector
sudo journalctl -u ai-soc-linux-collector -f
```

Collector logs:

```text
/opt/ai-soc-linux-collector/logs/collector.log
```

## Reboot Verification

```bash
systemctl is-enabled ai-soc-linux-collector
systemctl is-active ai-soc-linux-collector
```

Expected:
- enabled: `enabled`
- active: `active`

## Troubleshooting

- `config exists: no`: run `sudo bash install.sh --repair`.
- `backend reachable: no`: verify backend URL and `curl http://<backend>/health/ready`.
- `test event rejected`: invalid token, disabled collector, or backend ingest failure.
