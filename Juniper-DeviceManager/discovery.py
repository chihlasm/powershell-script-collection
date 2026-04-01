"""
Network discovery - scan subnets for Juniper devices via TCP probe + NETCONF.
"""

import ipaddress
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from netconf_ops import connect_device, get_device_facts, close_device


def tcp_probe(host, ports=(830, 22), timeout=1.5):
    """Quick TCP connect probe. Returns the first responsive port or None."""
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((str(host), port))
            sock.close()
            if result == 0:
                return port
        except Exception:
            pass
    return None


def scan_subnet(cidr, timeout=1.5, max_workers=50):
    """Scan a subnet for hosts with open NETCONF/SSH ports.
    Returns list of (ip, port) tuples."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return []

    responsive = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for host_ip in network.hosts():
            ip_str = str(host_ip)
            future = executor.submit(tcp_probe, ip_str, (830, 22), timeout)
            futures[future] = ip_str

        for future in as_completed(futures):
            ip_str = futures[future]
            try:
                port = future.result()
                if port is not None:
                    responsive.append((ip_str, port))
            except Exception:
                pass

    return responsive


def probe_device(host, username, password, port=830, timeout=15):
    """Connect to a device via NETCONF and get its facts.
    Returns (facts_dict, None) or (None, error_string)."""
    dev, err = connect_device(host, username, password, port=port, timeout=timeout)
    if err:
        return None, err
    try:
        facts = get_device_facts(dev)
        facts["host"] = host
        facts["port"] = port
        facts["status"] = "online"
        return facts, None
    except Exception as e:
        return None, f"error: {e}"
    finally:
        close_device(dev)


def discover_subnet(cidr, credential_groups, progress_callback=None, max_workers=10):
    """Full discovery: TCP scan a subnet, then NETCONF probe responsive hosts.

    credential_groups: list of dicts with keys: username, password, port
    progress_callback: called with (current, total, message) tuples

    Returns list of device dicts (successful probes) and list of error dicts.
    """
    if progress_callback:
        progress_callback(0, 0, f"Scanning {cidr}...")

    # Step 1: TCP scan
    responsive = scan_subnet(cidr)

    if progress_callback:
        progress_callback(0, len(responsive), f"Found {len(responsive)} responsive hosts. Probing via NETCONF...")

    if not responsive:
        return [], []

    devices = []
    errors = []
    completed = 0

    def _probe_with_creds(ip, port):
        """Try each credential group until one works."""
        for cred in credential_groups:
            cred_port = cred.get("port", port)
            facts, err = probe_device(ip, cred["username"], cred["password"], port=cred_port)
            if facts:
                facts["credential_group_id"] = cred.get("id")
                return facts, None
        return None, "auth_failed"

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for ip, port in responsive:
            future = executor.submit(_probe_with_creds, ip, port)
            futures[future] = ip

        for future in as_completed(futures):
            ip = futures[future]
            completed += 1
            try:
                facts, err = future.result()
                if facts:
                    devices.append(facts)
                    if progress_callback:
                        progress_callback(completed, len(responsive),
                            f"[PASS] {ip} - {facts.get('hostname', '')} ({facts.get('model', '')})")
                else:
                    errors.append({"host": ip, "error": err})
                    if progress_callback:
                        progress_callback(completed, len(responsive), f"[FAIL] {ip} - {err}")
            except Exception as e:
                errors.append({"host": ip, "error": str(e)})
                if progress_callback:
                    progress_callback(completed, len(responsive), f"[FAIL] {ip} - {e}")

    return devices, errors
