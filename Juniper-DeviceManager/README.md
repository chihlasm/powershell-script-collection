# Juniper-DeviceManager

> **Work in Progress** — This tool is in very early stages of development. Features described below may be incomplete, untested, or subject to significant change.

Browser-based fleet management tool for Juniper EX and SRX devices. Connects to devices via NETCONF to provide centralized inventory, configuration management, user management, and firmware upgrades.

## Features

- **Device Inventory** - Discover Juniper devices on configured subnets, monitor status, export to CSV
- **Config Management** - View, backup, compare (side-by-side diff), restore, and push configs to multiple devices
- **User Management** - Create, delete, and change passwords across multiple devices at once
- **Firmware Management** - Version matrix, register firmware images, upgrade multiple devices with progress tracking
- **Credential Encryption** - All stored passwords encrypted with AES (Fernet) using a master password
- **Dark/Light Theme** - Toggle between themes, persisted in browser

## Requirements

- Python 3.8+
- `junos-eznc` package (`pip install junos-eznc`)
- NETCONF enabled on target Juniper devices (port 830)

## Quick Start

```bash
# Install dependency
pip install junos-eznc

# Launch
python juniper_device_manager.py

# Or on Windows, double-click start.bat
```

Browser opens to `http://localhost:8290`. On first launch, set a master password to encrypt stored credentials.

## Setup Workflow

1. **Set Master Password** - Encrypts all stored device credentials
2. **Add Subnets** - Configure which networks to scan (e.g., `192.168.99.0/24`)
3. **Add Credential Groups** - Create named credential sets (e.g., "All Switches" with username/password/port)
4. **Scan Subnets** - Discover devices on the network
5. **Manage** - View configs, manage users, upgrade firmware

## Usage

```bash
# Default (port 8290, auto-open browser)
python juniper_device_manager.py

# Custom port
python juniper_device_manager.py --port 9090

# Don't auto-open browser
python juniper_device_manager.py --no-browser

# Custom database location
python juniper_device_manager.py --db /path/to/juniper_manager.db
```

## Portable Deployment

For deploying on client servers without Python installed:

1. Download Python embeddable package from python.org
2. Extract to `portable/python/`
3. Install pip and dependencies: `portable/python/python.exe -m pip install junos-eznc`
4. Double-click `start.bat`

The SQLite database (`juniper_manager.db`) persists in the script directory between sessions.

## Architecture

| File | Purpose |
|------|---------|
| `juniper_device_manager.py` | Entry point, arg parsing, HTTP server launch |
| `server.py` | Request handler, API route dispatch, thread pool |
| `db.py` | SQLite schema (7 tables), CRUD operations |
| `crypto.py` | Fernet encryption, master password management |
| `netconf_ops.py` | All junos-eznc device operations |
| `discovery.py` | Subnet scanning, device probing |
| `firmware.py` | Firmware file management, fleet upgrades |
| `html_content.py` | Embedded HTML/CSS/JS SPA |

## API

~35 REST API endpoints under `/api/`. Key groups:

- `/api/auth/*` - Master password setup, unlock, lock
- `/api/subnets` - Subnet CRUD
- `/api/credentials` - Credential group CRUD
- `/api/devices/*` - Device inventory, probe, config, users
- `/api/config/*` - Config compare, restore, push
- `/api/users/*` - Bulk user create, delete, password change
- `/api/firmware/*` - Image library, version matrix, upgrades
- `/api/jobs/*` - Async job tracking

## Security Notes

- Server binds to `127.0.0.1` only (localhost)
- Credentials encrypted at rest with Fernet (AES-128-CBC)
- Master password hashed with PBKDF2-SHA256 (480,000 iterations)
- Config pushes use `commit confirmed` (auto-rollback safety)
- No credentials are logged or exposed in API responses
