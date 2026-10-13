# JunOS - Info

Python script that audits Juniper (JunOS) network devices — pulls firmware versions and running configs from SRX firewalls and EX switches, then writes a summary CSV.

## Setup

1. Install the dependency: `pip install junos-eznc`
2. Copy `devices.example.csv` to `devices.csv` and list your devices.

`devices.csv` holds real hostnames and addresses, so it is listed in `.gitignore` and must never be committed.

### Device file columns

| Column | Required | Description |
|---|---|---|
| `name` | Yes | Device name used in output and config file names |
| `host` | Yes | Management IP or hostname |
| `location` | Yes | Site or room, shown in the report |
| `model_expected` | Yes | Model you expect (e.g. `SRX300`), compared against what the device reports |
| `type` | Yes | `srx` or `ex` — selects which credentials are used |
| `port` | No | NETCONF port. Defaults to 830; use 22 for older JunOS on SRX |

Lines whose name starts with `#` are skipped.

## Usage

```bash
python juniper_audit.py
python juniper_audit.py --devices C:\Audits\site-devices.csv --output-dir C:\Audits
python juniper_audit.py --type srx
```

Credentials are prompted at runtime and never written to disk.

## What It Does

- Connects to each device via NETCONF over SSH
- Records model, hostname, serial number, firmware version, and uptime
- Saves each running configuration to `configs/<device>.conf`
- Writes `firmware_summary.csv` and prints firmware versions grouped across devices
- Continues past unreachable devices or bad credentials and lists failures at the end

## Requirements

- Python 3.8+
- `junos-eznc`
- Network access to the Juniper management interfaces
