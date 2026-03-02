"""
Decatur Juniper Device Audit Script
Pulls firmware versions and running configs from all Juniper firewalls and switches.
Devices extracted from Decatur_Network_Diagram.vsdx

Usage:
    c:\temp\Python\python.exe decatur_juniper_audit.py

Requirements:
    pip install junos-eznc
"""

from jnpr.junos import Device
from jnpr.junos.exception import ConnectError, ConnectAuthError, ConnectTimeoutError
import csv
import os
import getpass
from datetime import datetime

# ============================================================================
# ALL DECATUR JUNIPER DEVICES (extracted from Visio network diagram)
# ============================================================================

DEVICES = [
    # --- FIREWALLS (SRX) - use port 22 (NETCONF over SSH) due to old Junos ---
    {"name": "DEC-CH-SRX340-01",    "host": "10.5.70.1",      "location": "City Hall",                "model_expected": "SRX340",  "type": "srx",  "port": 22},
    {"name": "DEC-PD-SRX300-01",    "host": "10.5.50.1",      "location": "Police Dept",              "model_expected": "SRX300",  "type": "srx",  "port": 22},
    {"name": "DEC-VC-SRX300-01",    "host": "10.129.28.1",    "location": "Visitor's Center",         "model_expected": "SRX300",  "type": "srx",  "port": 22},

    # --- CORE / RING SWITCHES (EX3400 - Ring Management IPs) ---
    {"name": "DEC-CH-EX3400-01",    "host": "192.168.99.1",   "location": "City Hall",                "model_expected": "EX3400",  "type": "ex"},
    {"name": "DEC-RC-EX3400-01",    "host": "192.168.99.10",  "location": "Sycamore Rec",             "model_expected": "EX3400",  "type": "ex"},
    {"name": "DEC-PW-EX3400-01",    "host": "192.168.99.12",  "location": "Public Works",             "model_expected": "EX3400",  "type": "ex"},
    {"name": "DEC-PD-EX3400-01",    "host": "192.168.99.16",  "location": "Police Dept",              "model_expected": "EX3400",  "type": "ex"},
    {"name": "DEC-FS1-EX3400-01",   "host": "192.168.99.20",  "location": "Fire Station 1",           "model_expected": "EX3400",  "type": "ex"},
    {"name": "DEC-FS2-EX3400-01",   "host": "192.168.99.22",  "location": "Fire Station 2",           "model_expected": "EX3400",  "type": "ex"},
    {"name": "DEC-TC-EX3400-01",    "host": "192.168.99.26",  "location": "Glenlake Park",            "model_expected": "EX3400",  "type": "ex"},
    {"name": "DEC-EG-EX3400-01",    "host": "192.168.99.38",  "location": "Ebster Gym",               "model_expected": "EX3400",  "type": "ex"},
    {"name": "DEC-LP-EX3400-01",    "host": "192.168.99.40",  "location": "Legacy Park",              "model_expected": "EX3400",  "type": "ex"},
    {"name": "DEC-CM-EX3400-01",    "host": "192.168.99.42",  "location": "Cemetery",                 "model_expected": "EX3400",  "type": "ex"},
    {"name": "DEC-MP-EX3400-01",    "host": "192.168.99.44",  "location": "McKoy Park",               "model_expected": "EX3400",  "type": "ex"},
    {"name": "DEC-OP-EX3400-01",    "host": "192.168.99.46",  "location": "Oakhurst Park",            "model_expected": "EX3400",  "type": "ex"},
    {"name": "DEC-BGC-EX3400-01",   "host": "192.168.99.48",  "location": "Oakhurst Rec (B&G Club)",  "model_expected": "EX3400",  "type": "ex"},
    {"name": "DEC-CC-EX3400-01",    "host": "192.168.99.50",  "location": "Community Center",         "model_expected": "EX3400",  "type": "ex"},

    # --- ACCESS SWITCHES (EX2300) ---
    {"name": "DEC-CH-EX2300-01",        "host": "10.5.0.2",       "location": "City Hall",                "model_expected": "EX2300",  "type": "ex"},
    {"name": "DEC-PD-EX2300-01",        "host": "10.5.16.2",      "location": "Police Dept",              "model_expected": "EX2300",  "type": "ex"},
    {"name": "DEC-PD-EX2300-CAMERA",    "host": "10.5.16.3",      "location": "Police Dept",              "model_expected": "EX2300",  "type": "ex"},
    {"name": "DEC-EBP-EX2300-01",       "host": "10.129.51.2",    "location": "Ebster Pool House",        "model_expected": "EX2300",  "type": "ex"},
    {"name": "DEC-RC-EX2300-01",        "host": "10.129.10.2",    "location": "Sycamore Rec",             "model_expected": "EX2300",  "type": "ex"},
    {"name": "DEC-LP-EX2300-01",        "host": "10.129.40.2",    "location": "Legacy Park",              "model_expected": "EX2300",  "type": "ex"},
    {"name": "DEC-LP-FCL-EX2300-01",    "host": "10.129.40.3",    "location": "Legacy Park Facilities",   "model_expected": "EX2300",  "type": "ex"},
    {"name": "DEC-LP-GYM-EX2300-01",    "host": "10.129.40.4",    "location": "Legacy Park Gym",          "model_expected": "EX2300",  "type": "ex"},
    {"name": "DEC-PW-EX2300-01",        "host": "10.129.12.2",    "location": "Public Works",             "model_expected": "EX2300",  "type": "ex"},
    {"name": "DEC-PW-EX2300-02",        "host": "10.129.12.3",    "location": "Public Works",             "model_expected": "EX2300",  "type": "ex"},
    {"name": "DEC-PW-MS-EX2300-01",     "host": "10.129.12.4",    "location": "Public Works Maint Shop",  "model_expected": "EX2300",  "type": "ex"},
    {"name": "DEC-PW-Annex-EX2300-01",  "host": "10.129.12.5",    "location": "Public Works Annex",       "model_expected": "EX2300",  "type": "ex"},
    {"name": "DEC-GLP-EX2300-01",       "host": "10.129.26.2",    "location": "Glenlake Pool House",      "model_expected": "EX2300",  "type": "ex"},
    {"name": "DEC-VC-EX2300-01",        "host": "10.129.28.2",    "location": "Visitor's Center",         "model_expected": "EX2300",  "type": "ex"},
]


def main():
    print("=" * 70)
    print("  Decatur Juniper Device Audit")
    print(f"  {len(DEVICES)} devices ({len([d for d in DEVICES if 'SRX' in d['model_expected']])} firewalls, "
          f"{len([d for d in DEVICES if 'EX3400' in d['model_expected']])} core switches, "
          f"{len([d for d in DEVICES if 'EX2300' in d['model_expected']])} access switches)")
    print("=" * 70)

    # Get credentials
    print("\n--- Credentials ---")
    print("If the SRX firewalls and EX switches use the same credentials,")
    print("just enter the same info for both.\n")

    print("SRX Firewall credentials:")
    srx_user = input("  Username: ")
    srx_pass = getpass.getpass("  Password: ")

    print("\nEX Switch credentials:")
    same = input("  Same as SRX? (y/n): ").strip().lower()
    if same == "y":
        ex_user = srx_user
        ex_pass = srx_pass
    else:
        ex_user = input("  Username: ")
        ex_pass = getpass.getpass("  Password: ")

    creds = {
        "srx": {"username": srx_user, "password": srx_pass},
        "ex":  {"username": ex_user,  "password": ex_pass},
    }

    # Create output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    output_dir = f"Decatur_Audit_{timestamp}"
    config_dir = os.path.join(output_dir, "configs")
    os.makedirs(config_dir, exist_ok=True)

    results = []
    success_count = 0
    fail_count = 0

    devices = [d for d in DEVICES if d ["type"] == "srx"]  # Filter devices by types we have credentials for
    for i, d in enumerate(devices, 1):
        print(f"\n[{i}/{len(DEVICES)}] {d['name']} ({d['host']}) - {d['location']}")

        device_creds = creds[d["type"]]
        port = d.get("port", 830)

        try:
            dev = Device(
                host=d["host"],
                user=device_creds["username"],
                passwd=device_creds["password"],
                port=port,
                timeout=30,
                auto_probe=5,
                normalize=True
            )
            dev.open()

            # Pull device facts
            facts = dev.facts
            version = facts.get("version", "Unknown")
            model = facts.get("model", "Unknown")
            hostname = facts.get("hostname", "Unknown")
            serial = facts.get("serialnumber", "Unknown")

            # Handle serial number (can be a list for virtual chassis)
            if isinstance(serial, list):
                serial = " / ".join(serial)

            # Get uptime from RE0
            re0 = facts.get("RE0", {})
            uptime = str(re0.get("up_time", "Unknown")) if re0 else "Unknown"

            # Pull running config as text
            config = dev.rpc.get_config(options={"format": "text"})
            config_text = config.text

            # Save config to file
            safe_name = d["name"].replace(" ", "_")
            config_file = os.path.join(config_dir, f"{safe_name}.conf")
            with open(config_file, "w") as f:
                f.write(config_text)

            results.append({
                "name": d["name"],
                "host": d["host"],
                "location": d["location"],
                "expected_model": d["model_expected"],
                "actual_model": model,
                "hostname": hostname,
                "serial": serial,
                "firmware": version,
                "uptime": uptime,
                "config_file": config_file,
                "status": "OK"
            })

            dev.close()
            success_count += 1
            print(f"  OK  |  {model}  |  Junos {version}  |  SN: {serial}  |  Up: {uptime}")

        except ConnectAuthError:
            fail_count += 1
            results.append({
                "name": d["name"], "host": d["host"], "location": d["location"],
                "expected_model": d["model_expected"], "actual_model": "", "hostname": "",
                "serial": "", "firmware": "", "uptime": "", "config_file": "",
                "status": "AUTH FAILED"
            })
            print(f"  FAIL  |  Authentication failed")

        except ConnectTimeoutError:
            fail_count += 1
            results.append({
                "name": d["name"], "host": d["host"], "location": d["location"],
                "expected_model": d["model_expected"], "actual_model": "", "hostname": "",
                "serial": "", "firmware": "", "uptime": "", "config_file": "",
                "status": "TIMEOUT"
            })
            print(f"  FAIL  |  Connection timed out (device unreachable?)")

        except ConnectError as e:
            fail_count += 1
            results.append({
                "name": d["name"], "host": d["host"], "location": d["location"],
                "expected_model": d["model_expected"], "actual_model": "", "hostname": "",
                "serial": "", "firmware": "", "uptime": "", "config_file": "",
                "status": f"CONNECT ERROR: {e}"
            })
            print(f"  FAIL  |  {e}")

        except Exception as e:
            fail_count += 1
            results.append({
                "name": d["name"], "host": d["host"], "location": d["location"],
                "expected_model": d["model_expected"], "actual_model": "", "hostname": "",
                "serial": "", "firmware": "", "uptime": "", "config_file": "",
                "status": f"ERROR: {e}"
            })
            print(f"  FAIL  |  {e}")

    # Write summary CSV
    csv_file = os.path.join(output_dir, "firmware_summary.csv")
    with open(csv_file, "w", newline="") as f:
        fieldnames = ["name", "host", "location", "expected_model", "actual_model",
                      "hostname", "serial", "firmware", "uptime", "config_file", "status"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    # Print summary
    print("\n" + "=" * 70)
    print(f"  AUDIT COMPLETE")
    print(f"  Succeeded: {success_count}/{len(DEVICES)}")
    print(f"  Failed:    {fail_count}/{len(DEVICES)}")
    print(f"  Output:    {os.path.abspath(output_dir)}")
    print(f"  Summary:   {csv_file}")
    print(f"  Configs:   {config_dir}")
    print("=" * 70)

    # Print firmware version summary
    if success_count > 0:
        print("\n  FIRMWARE VERSIONS FOUND:")
        versions = {}
        for r in results:
            if r["status"] == "OK":
                v = r["firmware"]
                if v not in versions:
                    versions[v] = []
                versions[v].append(r["name"])
        for v, names in sorted(versions.items()):
            print(f"    Junos {v}: {len(names)} devices")
            for n in names:
                print(f"      - {n}")

    if fail_count > 0:
        print("\n  FAILED DEVICES:")
        for r in results:
            if r["status"] != "OK":
                print(f"    {r['name']:30s} {r['host']:20s} {r['status']}")


if __name__ == "__main__":
    main()