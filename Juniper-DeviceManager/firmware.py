"""
Firmware file management and fleet upgrade orchestration.
"""

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from netconf_ops import connect_device, close_device, install_firmware


def validate_firmware_file(filepath):
    """Validate a firmware file exists and compute metadata."""
    if not os.path.isfile(filepath):
        return None, f"File not found: {filepath}"

    filename = os.path.basename(filepath)
    file_size = os.path.getsize(filepath)

    # Compute MD5
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)

    return {
        "filename": filename,
        "filepath": os.path.abspath(filepath),
        "file_size": file_size,
        "md5_hash": md5.hexdigest(),
    }, None


def run_fleet_upgrade(devices, image_path, reboot, credential_resolver, progress_callback=None, max_workers=2):
    """Upgrade firmware on multiple devices.

    devices: list of device dicts (from DB)
    image_path: local path to firmware .tgz
    reboot: bool
    credential_resolver: function(device) -> (username, password, port)
    progress_callback: function(device_id, status, message)
    max_workers: concurrent upgrades (default 2 - firmware is bandwidth heavy)

    Returns dict of {device_id: result_dict}
    """
    results = {}

    def _upgrade_one(device):
        device_id = device["id"]
        host = device["host"]

        if progress_callback:
            progress_callback(device_id, "connecting", f"Connecting to {host}...")

        username, password, port = credential_resolver(device)
        dev, err = connect_device(host, username, password, port=port, timeout=60)
        if err:
            if progress_callback:
                progress_callback(device_id, "failed", f"Connection failed: {err}")
            return device_id, {"success": False, "message": f"Connection failed: {err}"}

        try:
            if progress_callback:
                progress_callback(device_id, "installing", f"Installing firmware on {host}...")

            def _fw_progress(report):
                if progress_callback:
                    progress_callback(device_id, "installing", str(report))

            result = install_firmware(dev, image_path, reboot=reboot, progress_callback=_fw_progress)

            status = "completed" if result["success"] else "failed"
            if progress_callback:
                progress_callback(device_id, status, result["message"])

            return device_id, result
        finally:
            close_device(dev)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_upgrade_one, d): d for d in devices}
        for future in as_completed(futures):
            try:
                device_id, result = future.result()
                results[device_id] = result
            except Exception as e:
                device = futures[future]
                results[device["id"]] = {"success": False, "message": str(e)}

    return results
