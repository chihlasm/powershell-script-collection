# JunOS - Info

Python script that audits Juniper (JunOS) network devices — pulls firmware versions and running configs from all firewalls and switches.

## Usage

```bash
c:\temp\Python\python.exe decatur_juniper_audit.py
```

## What It Does

- Connects to each Juniper device via NETCONF (SSH)
- Retrieves firmware version and running configuration
- Exports results to CSV

## Device Types

- **SRX Firewalls** — connects on port 22 (NETCONF over SSH for older JunOS)
- **EX Switches** — core ring switches (EX3400) and access switches (EX2300)

## Requirements

- Python 3.x
- `junos-eznc` package (`pip install junos-eznc`)
- Network access to Juniper management interfaces
- Valid device credentials (prompted at runtime)
