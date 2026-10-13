"""
Juniper Device Audit
Pulls firmware versions and running configs from Juniper SRX firewalls and EX switches.

The device inventory is read from a CSV file at runtime, so no site-specific
hostnames or addresses live in this script. Copy devices.example.csv to
devices.csv, fill in your devices, and keep devices.csv out of source control
(it is listed in the repository .gitignore).

Usage:
    python juniper_audit.py
    python juniper_audit.py --devices C:\\Audits\\site-devices.csv --output-dir C:\\Audits
    python juniper_audit.py --type srx          # firewalls only

Requirements:
    pip install junos-eznc
"""

import argparse
import csv
import getpass
import os
import sys
from datetime import datetime

from jnpr.junos import Device
from jnpr.junos.exception import ConnectAuthError, ConnectError, ConnectTimeoutError

REQUIRED_COLUMNS = {"name", "host", "location", "model_expected", "type"}
VALID_TYPES = {"srx", "ex"}
DEFAULT_NETCONF_PORT = 830
RESULT_FIELDS = ["name", "host", "location", "expected_model", "actual_model",
                 "hostname", "serial", "firmware", "uptime", "config_file", "status"]


def load_devices(path):
    """Read and validate the device inventory CSV."""
    if not os.path.isfile(path):
        sys.exit(f"Device file not found: {path}\n"
                 f"Copy devices.example.csv to devices.csv and add your devices.")

    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            sys.exit(f"Device file is missing column(s): {', '.join(sorted(missing))}")

        devices = []
        for line_no, row in enumerate(reader, start=2):
            row = {k: (v or "").strip() for k, v in row.items()}
            if not row["name"] or row["name"].startswith("#"):
                continue
            row["type"] = row["type"].lower()
            if row["type"] not in VALID_TYPES:
                sys.exit(f"Line {line_no}: type must be 'srx' or 'ex' (got '{row['type']}')")
            port = row.get("port") or ""
            if port and not port.isdigit():
                sys.exit(f"Line {line_no}: port must be a number (got '{port}')")
            row["port"] = int(port) if port else DEFAULT_NETCONF_PORT
            devices.append(row)

    if not devices:
        sys.exit(f"No devices found in {path}")
    return devices


def prompt_credentials(types_needed):
    """Prompt for credentials once per device type; offer to reuse SRX creds for EX."""
    print("\n--- Credentials ---")
    creds = {}
    if "srx" in types_needed:
        print("SRX firewall credentials:")
        creds["srx"] = {"username": input("  Username: "), "password": getpass.getpass("  Password: ")}
    if "ex" in types_needed:
        print("\nEX switch credentials:")
        if "srx" in creds and input("  Same as SRX? (y/n): ").strip().lower() == "y":
            creds["ex"] = creds["srx"]
        else:
            creds["ex"] = {"username": input("  Username: "), "password": getpass.getpass("  Password: ")}
    return creds


def failed_result(d, status):
    return {"name": d["name"], "host": d["host"], "location": d["location"],
            "expected_model": d["model_expected"], "actual_model": "", "hostname": "",
            "serial": "", "firmware": "", "uptime": "", "config_file": "", "status": status}


def audit_device(d, device_creds, config_dir):
    """Connect to one device, save its running config, and return a result row."""
    dev = Device(host=d["host"], user=device_creds["username"], passwd=device_creds["password"],
                 port=d["port"], timeout=30, auto_probe=5, normalize=True)
    dev.open()
    try:
        facts = dev.facts
        serial = facts.get("serialnumber", "Unknown")
        if isinstance(serial, list):  # virtual chassis returns one serial per member
            serial = " / ".join(serial)
        re0 = facts.get("RE0") or {}

        config_text = dev.rpc.get_config(options={"format": "text"}).text
        config_file = os.path.join(config_dir, f"{d['name'].replace(' ', '_')}.conf")
        with open(config_file, "w", encoding="utf-8") as f:
            f.write(config_text)

        return {"name": d["name"], "host": d["host"], "location": d["location"],
                "expected_model": d["model_expected"], "actual_model": facts.get("model", "Unknown"),
                "hostname": facts.get("hostname", "Unknown"), "serial": serial,
                "firmware": facts.get("version", "Unknown"),
                "uptime": str(re0.get("up_time", "Unknown")), "config_file": config_file,
                "status": "OK"}
    finally:
        dev.close()


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="Audit Juniper SRX/EX firmware and running configs.")
    parser.add_argument("--devices", default=os.path.join(script_dir, "devices.csv"),
                        help="Device inventory CSV (default: devices.csv beside this script)")
    parser.add_argument("--output-dir", default=".",
                        help="Folder for the audit output (default: current directory)")
    parser.add_argument("--type", choices=sorted(VALID_TYPES),
                        help="Only audit one device type")
    args = parser.parse_args()

    devices = load_devices(args.devices)
    if args.type:
        devices = [d for d in devices if d["type"] == args.type]
        if not devices:
            sys.exit(f"No '{args.type}' devices in {args.devices}")

    print("=" * 70)
    print("  Juniper Device Audit")
    print(f"  {len(devices)} devices "
          f"({sum(d['type'] == 'srx' for d in devices)} firewalls, "
          f"{sum(d['type'] == 'ex' for d in devices)} switches)")
    print("=" * 70)

    creds = prompt_credentials({d["type"] for d in devices})

    output_dir = os.path.join(args.output_dir, f"Juniper_Audit_{datetime.now():%Y%m%d_%H%M}")
    config_dir = os.path.join(output_dir, "configs")
    os.makedirs(config_dir, exist_ok=True)

    results = []
    for i, d in enumerate(devices, 1):
        print(f"\n[{i}/{len(devices)}] {d['name']} ({d['host']}) - {d['location']}")
        try:
            r = audit_device(d, creds[d["type"]], config_dir)
            print(f"  OK  |  {r['actual_model']}  |  Junos {r['firmware']}  |  "
                  f"SN: {r['serial']}  |  Up: {r['uptime']}")
        except ConnectAuthError:
            r = failed_result(d, "AUTH FAILED")
            print("  FAIL  |  Authentication failed")
        except ConnectTimeoutError:
            r = failed_result(d, "TIMEOUT")
            print("  FAIL  |  Connection timed out (device unreachable?)")
        except ConnectError as e:
            r = failed_result(d, f"CONNECT ERROR: {e}")
            print(f"  FAIL  |  {e}")
        except Exception as e:  # keep going so one bad device doesn't stop the audit
            r = failed_result(d, f"ERROR: {e}")
            print(f"  FAIL  |  {e}")
        results.append(r)

    csv_file = os.path.join(output_dir, "firmware_summary.csv")
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=RESULT_FIELDS)
        writer.writeheader()
        writer.writerows(results)

    ok = [r for r in results if r["status"] == "OK"]
    failed = [r for r in results if r["status"] != "OK"]

    print("\n" + "=" * 70)
    print("  AUDIT COMPLETE")
    print(f"  Succeeded: {len(ok)}/{len(results)}")
    print(f"  Failed:    {len(failed)}/{len(results)}")
    print(f"  Output:    {os.path.abspath(output_dir)}")
    print(f"  Summary:   {csv_file}")
    print("=" * 70)

    if ok:
        print("\n  FIRMWARE VERSIONS FOUND:")
        versions = {}
        for r in ok:
            versions.setdefault(r["firmware"], []).append(r["name"])
        for version, names in sorted(versions.items()):
            print(f"    Junos {version}: {len(names)} devices")
            for n in names:
                print(f"      - {n}")

    if failed:
        print("\n  FAILED DEVICES:")
        for r in failed:
            print(f"    {r['name']:30s} {r['host']:20s} {r['status']}")


if __name__ == "__main__":
    main()
