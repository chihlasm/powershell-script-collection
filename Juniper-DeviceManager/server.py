"""
HTTP request handler and API route dispatch for Juniper Device Manager.
"""

import csv
import difflib
import io
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import crypto
import db
import discovery as disc
import netconf_ops as nops
import firmware as fw
from html_content import HTML_CONTENT

# Thread pool for concurrent NETCONF operations
executor = ThreadPoolExecutor(max_workers=10)

# Session log
session_log = []
_log_lock = threading.Lock()


def log(message, level="INFO"):
    entry = {"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "level": level, "message": message}
    with _log_lock:
        session_log.append(entry)
    colors = {"INFO": "\033[96m", "PASS": "\033[92m", "WARN": "\033[93m", "FAIL": "\033[91m"}
    reset = "\033[0m"
    c = colors.get(level, "")
    print(f"{c}[{level}] {entry['time']}  {message}{reset}")


def _resolve_credentials(device):
    """Resolve credentials for a device (per-device override > group). Returns (username, password, port)."""
    if device.get("override_username") and device.get("override_password_enc"):
        return (
            device["override_username"],
            crypto.decrypt_password(device["override_password_enc"]),
            device.get("override_port") or 830
        )
    if device.get("credential_group_id"):
        group = db.get_credential_group(device["credential_group_id"])
        if group:
            return (
                group["username"],
                crypto.decrypt_password(group["password_enc"]),
                group["port"]
            )
    return None, None, None


class JuniperManagerHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # Suppress default HTTP logging

    # ---- Response helpers ----
    def _send_json(self, data, status=200):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_csv(self, csv_data, filename):
        body = csv_data.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def _require_auth(self):
        """Check session is unlocked. Returns True if OK, sends 401 and returns False if not."""
        if not crypto.is_unlocked():
            self._send_json({"success": False, "message": "Session is locked. Unlock with master password."}, 401)
            return False
        return True

    def _path_id(self, pattern):
        """Extract an integer ID from a URL path using regex. Returns int or None."""
        m = re.match(pattern, urlparse(self.path).path)
        return int(m.group(1)) if m else None

    # ---- GET routes ----
    def do_GET(self):
        path = urlparse(self.path).path

        if path in ("/", "/index.html"):
            self._send_html(HTML_CONTENT)
            return

        # Auth
        if path == "/api/auth/status":
            has_master = db.get_setting("master_password_hash") is not None
            self._send_json({"hasMasterPassword": has_master, "unlocked": crypto.is_unlocked()})
            return

        # Log (no auth required)
        if path == "/api/log":
            self._send_json({"entries": session_log[-500:]})
            return

        # Everything below requires auth
        if not self._require_auth():
            return

        # Subnets
        if path == "/api/subnets":
            self._send_json({"subnets": db.get_subnets()})
            return

        # Credentials
        if path == "/api/credentials":
            groups = db.get_credential_groups()
            # Mask passwords
            for g in groups:
                g["password_enc"] = "***"
            self._send_json({"credentials": groups})
            return

        # Devices
        if path == "/api/devices":
            self._send_json({"devices": db.get_devices()})
            return

        if path == "/api/devices/export":
            devices = db.get_devices()
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=[
                "host", "hostname", "model", "firmware_version", "serial_number",
                "uptime", "device_type", "status", "last_seen", "notes"
            ], extrasaction="ignore")
            writer.writeheader()
            writer.writerows(devices)
            self._send_csv(output.getvalue(), f"juniper_inventory_{datetime.now().strftime('%Y%m%d_%H%M')}.csv")
            return

        # Device detail
        device_id = self._path_id(r'/api/devices/(\d+)$')
        if device_id is not None:
            device = db.get_device(device_id)
            if not device:
                self._send_json({"success": False, "message": "Device not found."}, 404)
                return
            self._send_json({"device": device})
            return

        # Config backups for device
        device_id = self._path_id(r'/api/devices/(\d+)/config/backups$')
        if device_id is not None:
            backups = db.get_config_backups(device_id)
            self._send_json({"backups": backups})
            return

        # Device users
        device_id = self._path_id(r'/api/devices/(\d+)/users$')
        if device_id is not None:
            device = db.get_device(device_id)
            if not device:
                self._send_json({"success": False, "message": "Device not found."}, 404)
                return
            username, password, port = _resolve_credentials(device)
            if not username:
                self._send_json({"success": False, "message": "No credentials for this device."})
                return
            dev, err = nops.connect_device(device["host"], username, password, port=port)
            if err:
                self._send_json({"success": False, "message": f"Connection failed: {err}"})
                return
            try:
                users = nops.get_users(dev)
                self._send_json({"success": True, "users": users})
            finally:
                nops.close_device(dev)
            return

        # Device live config
        device_id = self._path_id(r'/api/devices/(\d+)/config$')
        if device_id is not None:
            device = db.get_device(device_id)
            if not device:
                self._send_json({"success": False, "message": "Device not found."}, 404)
                return
            username, password, port = _resolve_credentials(device)
            if not username:
                self._send_json({"success": False, "message": "No credentials for this device."})
                return
            dev, err = nops.connect_device(device["host"], username, password, port=port)
            if err:
                self._send_json({"success": False, "message": f"Connection failed: {err}"})
                return
            try:
                config = nops.get_running_config(dev)
                self._send_json({"success": True, "config": config})
            finally:
                nops.close_device(dev)
            return

        # Config backup detail
        backup_id = self._path_id(r'/api/config/backups/(\d+)$')
        if backup_id is not None:
            backup = db.get_config_backup(backup_id)
            if not backup:
                self._send_json({"success": False, "message": "Backup not found."}, 404)
                return
            self._send_json({"backup": backup})
            return

        # Firmware
        if path == "/api/firmware/images":
            self._send_json({"images": db.get_firmware_images()})
            return

        if path == "/api/firmware/matrix":
            devices = db.get_devices()
            images = db.get_firmware_images()
            # Build version matrix
            matrix = []
            for d in devices:
                available = [img for img in images if img["platform"].upper() in (d.get("model") or "").upper()]
                latest = available[0] if available else None
                matrix.append({
                    "device_id": d["id"],
                    "host": d["host"],
                    "hostname": d["hostname"],
                    "model": d["model"],
                    "current_version": d["firmware_version"],
                    "available_version": latest["version"] if latest else None,
                    "available_image_id": latest["id"] if latest else None,
                    "needs_upgrade": latest["version"] != d["firmware_version"] if latest else False,
                })
            self._send_json({"matrix": matrix})
            return

        # Jobs
        if path == "/api/jobs":
            self._send_json({"jobs": db.get_jobs()})
            return

        job_id = self._path_id(r'/api/jobs/(\d+)$')
        if job_id is not None:
            job = db.get_job(job_id)
            if not job:
                self._send_json({"success": False, "message": "Job not found."}, 404)
                return
            self._send_json({"job": job})
            return

        self._send_json({"error": "Not found"}, 404)

    # ---- POST routes ----
    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()

        # ---- Auth (no auth check) ----
        if path == "/api/auth/setup":
            if db.get_setting("master_password_hash"):
                self._send_json({"success": False, "message": "Master password already set."})
                return
            pw = body.get("password", "")
            if len(pw) < 8:
                self._send_json({"success": False, "message": "Password must be at least 8 characters."})
                return
            pw_hash = crypto.hash_master_password(pw)
            db.set_setting("master_password_hash", pw_hash)
            # Extract salt and unlock
            salt_hex = pw_hash.split(":")[0]
            db.set_setting("encryption_salt", salt_hex)
            crypto.unlock(pw, salt_hex)
            log("Master password set. Session unlocked.", "PASS")
            self._send_json({"success": True, "message": "Master password set."})
            return

        if path == "/api/auth/unlock":
            stored = db.get_setting("master_password_hash")
            if not stored:
                self._send_json({"success": False, "message": "No master password set. Run setup first."})
                return
            pw = body.get("password", "")
            if not crypto.verify_master_password(pw, stored):
                log("Unlock attempt failed - wrong password.", "FAIL")
                self._send_json({"success": False, "message": "Wrong password."})
                return
            salt_hex = db.get_setting("encryption_salt", stored.split(":")[0])
            crypto.unlock(pw, salt_hex)
            log("Session unlocked.", "PASS")
            self._send_json({"success": True, "message": "Session unlocked."})
            return

        if path == "/api/auth/lock":
            crypto.lock()
            log("Session locked.", "INFO")
            self._send_json({"success": True, "message": "Session locked."})
            return

        # ---- Everything below requires auth ----
        if not self._require_auth():
            return

        # ---- Subnets ----
        if path == "/api/subnets":
            cidr = body.get("cidr", "").strip()
            label = body.get("label", "").strip()
            if not cidr:
                self._send_json({"success": False, "message": "CIDR is required."})
                return
            try:
                import ipaddress
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                self._send_json({"success": False, "message": "Invalid CIDR notation."})
                return
            try:
                sid = db.add_subnet(cidr, label)
                log(f"Added subnet: {cidr} ({label})", "PASS")
                self._send_json({"success": True, "message": f"Subnet {cidr} added.", "id": sid})
            except Exception as e:
                self._send_json({"success": False, "message": f"Error: {e}"})
            return

        subnet_id = self._path_id(r'/api/subnets/(\d+)/delete$')
        if subnet_id is not None:
            db.delete_subnet(subnet_id)
            log(f"Deleted subnet ID {subnet_id}", "INFO")
            self._send_json({"success": True})
            return

        # ---- Credentials ----
        if path == "/api/credentials":
            name = body.get("name", "").strip()
            username = body.get("username", "").strip()
            password = body.get("password", "")
            port = int(body.get("port", 830))
            cred_id = body.get("id")

            if not name or not username or not password:
                self._send_json({"success": False, "message": "Name, username, and password are required."})
                return

            password_enc = crypto.encrypt_password(password)

            if cred_id:
                db.update_credential_group(cred_id, name=name, username=username, password_enc=password_enc, port=port)
                log(f"Updated credential group: {name}", "PASS")
                self._send_json({"success": True, "message": f"Credential group '{name}' updated."})
            else:
                try:
                    new_id = db.add_credential_group(name, username, password_enc, port)
                    log(f"Created credential group: {name}", "PASS")
                    self._send_json({"success": True, "message": f"Credential group '{name}' created.", "id": new_id})
                except Exception as e:
                    self._send_json({"success": False, "message": f"Error: {e}"})
            return

        cred_id = self._path_id(r'/api/credentials/(\d+)/delete$')
        if cred_id is not None:
            db.delete_credential_group(cred_id)
            log(f"Deleted credential group ID {cred_id}", "INFO")
            self._send_json({"success": True})
            return

        # ---- Discovery ----
        if path == "/api/discover":
            subnet_ids = body.get("subnet_ids", [])
            subnets = db.get_subnets()
            if subnet_ids:
                subnets = [s for s in subnets if s["id"] in subnet_ids]
            subnets = [s for s in subnets if s["enabled"]]

            if not subnets:
                self._send_json({"success": False, "message": "No subnets configured or enabled."})
                return

            cred_groups = db.get_credential_groups()
            if not cred_groups:
                self._send_json({"success": False, "message": "No credential groups configured."})
                return

            # Decrypt passwords for use
            creds = []
            for g in cred_groups:
                try:
                    creds.append({
                        "id": g["id"],
                        "username": g["username"],
                        "password": crypto.decrypt_password(g["password_enc"]),
                        "port": g["port"],
                    })
                except Exception:
                    pass

            all_device_ids = [d["id"] for d in db.get_devices()]
            job_id = db.create_job("discovery", all_device_ids, {"subnets": [s["cidr"] for s in subnets]})
            log(f"Starting discovery scan on {len(subnets)} subnet(s)...", "INFO")

            def _run_discovery():
                total_found = 0
                total_errors = 0
                for subnet in subnets:
                    def _progress(current, total, message):
                        db.update_job_progress(job_id, {
                            "subnet": subnet["cidr"],
                            "current": current,
                            "total": total,
                            "message": message,
                        })
                        log(message, "INFO")

                    devices, errors = disc.discover_subnet(subnet["cidr"], creds, progress_callback=_progress)
                    for d in devices:
                        db.upsert_device(
                            d["host"],
                            hostname=d.get("hostname", ""),
                            model=d.get("model", ""),
                            serial_number=d.get("serial_number", ""),
                            firmware_version=d.get("firmware_version", ""),
                            uptime=d.get("uptime", ""),
                            device_type=d.get("device_type", ""),
                            status="online",
                            last_seen=datetime.utcnow().isoformat(),
                            credential_group_id=d.get("credential_group_id"),
                        )
                    for e in errors:
                        db.upsert_device(e["host"], status=e["error"])
                    total_found += len(devices)
                    total_errors += len(errors)

                db.complete_job(job_id)
                log(f"Discovery complete: {total_found} devices found, {total_errors} errors.", "PASS")

            executor.submit(_run_discovery)
            self._send_json({"success": True, "message": "Discovery started.", "jobId": job_id})
            return

        # ---- Device operations ----
        device_id = self._path_id(r'/api/devices/(\d+)/probe$')
        if device_id is not None:
            device = db.get_device(device_id)
            if not device:
                self._send_json({"success": False, "message": "Device not found."}, 404)
                return
            username, password, port = _resolve_credentials(device)
            if not username:
                self._send_json({"success": False, "message": "No credentials for this device."})
                return

            dev, err = nops.connect_device(device["host"], username, password, port=port)
            if err:
                db.update_device_status(device_id, err)
                self._send_json({"success": False, "message": f"Connection failed: {err}"})
                return
            try:
                facts = nops.get_device_facts(dev)
                db.update_device(device_id,
                    hostname=facts["hostname"],
                    model=facts["model"],
                    firmware_version=facts["firmware_version"],
                    serial_number=facts["serial_number"],
                    uptime=facts["uptime"],
                    device_type=facts["device_type"],
                    status="online",
                    last_seen=datetime.utcnow().isoformat(),
                )
                log(f"Probed {device['host']}: {facts['hostname']} ({facts['model']})", "PASS")
                self._send_json({"success": True, "device": db.get_device(device_id)})
            finally:
                nops.close_device(dev)
            return

        device_id = self._path_id(r'/api/devices/(\d+)$')
        if device_id is not None and path.endswith(f"/{device_id}"):
            # Update device (notes, credential group, overrides)
            device = db.get_device(device_id)
            if not device:
                self._send_json({"success": False, "message": "Device not found."}, 404)
                return
            updates = {}
            if "notes" in body:
                updates["notes"] = body["notes"]
            if "credential_group_id" in body:
                updates["credential_group_id"] = body["credential_group_id"]
            if "override_username" in body:
                updates["override_username"] = body["override_username"]
            if "override_password" in body and body["override_password"]:
                updates["override_password_enc"] = crypto.encrypt_password(body["override_password"])
            if "override_port" in body:
                updates["override_port"] = body["override_port"]
            if updates:
                db.update_device(device_id, **updates)
            self._send_json({"success": True, "message": "Device updated."})
            return

        device_id = self._path_id(r'/api/devices/(\d+)/delete$')
        if device_id is not None:
            db.delete_device(device_id)
            log(f"Removed device ID {device_id}", "INFO")
            self._send_json({"success": True})
            return

        # ---- Config operations ----
        device_id = self._path_id(r'/api/devices/(\d+)/config/backup$')
        if device_id is not None:
            device = db.get_device(device_id)
            if not device:
                self._send_json({"success": False, "message": "Device not found."}, 404)
                return
            username, password, port = _resolve_credentials(device)
            if not username:
                self._send_json({"success": False, "message": "No credentials."})
                return
            dev, err = nops.connect_device(device["host"], username, password, port=port)
            if err:
                self._send_json({"success": False, "message": f"Connection failed: {err}"})
                return
            try:
                config = nops.get_running_config(dev)
                label = body.get("label", "")
                backup_id = db.add_config_backup(device_id, config, backup_type="manual", label=label)
                log(f"Config backup saved for {device['hostname']} ({device['host']})", "PASS")
                self._send_json({"success": True, "message": "Config backup saved.", "backupId": backup_id})
            finally:
                nops.close_device(dev)
            return

        if path == "/api/config/compare":
            backup_id_a = body.get("backup_id_a")
            backup_id_b = body.get("backup_id_b")
            device_id = body.get("device_id")

            config_a = ""
            config_b = ""
            label_a = ""
            label_b = ""

            if backup_id_a:
                ba = db.get_config_backup(backup_id_a)
                if ba:
                    config_a = ba["config_text"]
                    label_a = f"Backup #{backup_id_a} ({ba['created_at']})"

            if backup_id_b:
                bb = db.get_config_backup(backup_id_b)
                if bb:
                    config_b = bb["config_text"]
                    label_b = f"Backup #{backup_id_b} ({bb['created_at']})"
            elif device_id:
                # Compare backup_a against live config
                device = db.get_device(device_id)
                if device:
                    username, password, port = _resolve_credentials(device)
                    if username:
                        dev, err = nops.connect_device(device["host"], username, password, port=port)
                        if not err:
                            try:
                                config_b = nops.get_running_config(dev)
                                label_b = f"Live config ({device['host']})"
                            finally:
                                nops.close_device(dev)

            diff = list(difflib.unified_diff(
                config_a.splitlines(keepends=True),
                config_b.splitlines(keepends=True),
                fromfile=label_a,
                tofile=label_b,
            ))
            self._send_json({"success": True, "diff": "".join(diff), "label_a": label_a, "label_b": label_b})
            return

        if path == "/api/config/restore":
            device_id = body.get("device_id")
            backup_id = body.get("backup_id")
            if not device_id or not backup_id:
                self._send_json({"success": False, "message": "device_id and backup_id required."})
                return
            device = db.get_device(device_id)
            backup = db.get_config_backup(backup_id)
            if not device or not backup:
                self._send_json({"success": False, "message": "Device or backup not found."}, 404)
                return
            username, password, port = _resolve_credentials(device)
            if not username:
                self._send_json({"success": False, "message": "No credentials."})
                return
            dev, err = nops.connect_device(device["host"], username, password, port=port)
            if err:
                self._send_json({"success": False, "message": f"Connection failed: {err}"})
                return
            try:
                result = nops.restore_config(dev, backup["config_text"])
                if result["success"]:
                    log(f"Config restored on {device['host']} from backup #{backup_id}", "PASS")
                self._send_json(result)
            finally:
                nops.close_device(dev)
            return

        if path == "/api/config/push":
            device_ids = body.get("device_ids", [])
            commands = body.get("commands", [])
            comment = body.get("comment", "Pushed via Juniper Device Manager")

            if not device_ids or not commands:
                self._send_json({"success": False, "message": "device_ids and commands required."})
                return

            if isinstance(commands, str):
                commands = [c.strip() for c in commands.strip().splitlines() if c.strip()]

            results = {}
            for did in device_ids:
                device = db.get_device(did)
                if not device:
                    results[did] = {"success": False, "message": "Device not found."}
                    continue
                username, password, port = _resolve_credentials(device)
                if not username:
                    results[did] = {"success": False, "message": "No credentials."}
                    continue
                dev, err = nops.connect_device(device["host"], username, password, port=port)
                if err:
                    results[did] = {"success": False, "message": f"Connection failed: {err}"}
                    continue
                try:
                    result = nops.push_config(dev, commands, commit_comment=comment)
                    results[did] = result
                    status = "PASS" if result["success"] else "FAIL"
                    log(f"Config push to {device['host']}: {result['message']}", status)
                finally:
                    nops.close_device(dev)

            self._send_json({"success": True, "results": results})
            return

        # ---- User management (bulk) ----
        if path == "/api/users/create":
            device_ids = body.get("device_ids", [])
            username = body.get("username", "").strip()
            password = body.get("password", "")
            user_class = body.get("userClass", "super-user")
            if not device_ids or not username:
                self._send_json({"success": False, "message": "device_ids and username required."})
                return
            results = {}
            for did in device_ids:
                device = db.get_device(did)
                if not device:
                    results[did] = {"success": False, "message": "Not found."}
                    continue
                cred_user, cred_pass, cred_port = _resolve_credentials(device)
                if not cred_user:
                    results[did] = {"success": False, "message": "No credentials."}
                    continue
                dev, err = nops.connect_device(device["host"], cred_user, cred_pass, port=cred_port)
                if err:
                    results[did] = {"success": False, "message": f"Connection failed: {err}"}
                    continue
                try:
                    r = nops.create_user(dev, username, password, user_class)
                    if password:
                        r2 = nops.set_user_password(dev, username, password)
                        if not r2["success"]:
                            r = r2
                    results[did] = r
                    log(f"Create user '{username}' on {device['host']}: {r['message']}", "PASS" if r["success"] else "FAIL")
                finally:
                    nops.close_device(dev)
            self._send_json({"success": True, "results": results})
            return

        if path == "/api/users/delete":
            device_ids = body.get("device_ids", [])
            username = body.get("username", "").strip()
            if not device_ids or not username:
                self._send_json({"success": False, "message": "device_ids and username required."})
                return
            results = {}
            for did in device_ids:
                device = db.get_device(did)
                if not device:
                    results[did] = {"success": False, "message": "Not found."}
                    continue
                cred_user, cred_pass, cred_port = _resolve_credentials(device)
                if not cred_user:
                    results[did] = {"success": False, "message": "No credentials."}
                    continue
                dev, err = nops.connect_device(device["host"], cred_user, cred_pass, port=cred_port)
                if err:
                    results[did] = {"success": False, "message": f"Connection failed: {err}"}
                    continue
                try:
                    r = nops.delete_user(dev, username)
                    results[did] = r
                    log(f"Delete user '{username}' from {device['host']}: {r['message']}", "PASS" if r["success"] else "FAIL")
                finally:
                    nops.close_device(dev)
            self._send_json({"success": True, "results": results})
            return

        if path == "/api/users/change-password":
            device_ids = body.get("device_ids", [])
            username = body.get("username", "").strip()
            password = body.get("password", "")
            if not device_ids or not username or not password:
                self._send_json({"success": False, "message": "device_ids, username, and password required."})
                return
            results = {}
            for did in device_ids:
                device = db.get_device(did)
                if not device:
                    results[did] = {"success": False, "message": "Not found."}
                    continue
                cred_user, cred_pass, cred_port = _resolve_credentials(device)
                if not cred_user:
                    results[did] = {"success": False, "message": "No credentials."}
                    continue
                dev, err = nops.connect_device(device["host"], cred_user, cred_pass, port=cred_port)
                if err:
                    results[did] = {"success": False, "message": f"Connection failed: {err}"}
                    continue
                try:
                    r = nops.set_user_password(dev, username, password)
                    results[did] = r
                    log(f"Change password for '{username}' on {device['host']}: {r['message']}", "PASS" if r["success"] else "FAIL")
                finally:
                    nops.close_device(dev)
            self._send_json({"success": True, "results": results})
            return

        # ---- Firmware ----
        if path == "/api/firmware/images":
            filepath = body.get("filepath", "").strip()
            platform = body.get("platform", "").strip()
            version = body.get("version", "").strip()
            if not filepath or not platform or not version:
                self._send_json({"success": False, "message": "filepath, platform, and version required."})
                return
            meta, err = fw.validate_firmware_file(filepath)
            if err:
                self._send_json({"success": False, "message": err})
                return
            try:
                fid = db.add_firmware_image(meta["filename"], meta["filepath"], platform, version, meta["file_size"], meta["md5_hash"])
                log(f"Registered firmware: {platform} v{version} ({meta['filename']})", "PASS")
                self._send_json({"success": True, "message": "Firmware image registered.", "id": fid})
            except Exception as e:
                self._send_json({"success": False, "message": f"Error: {e}"})
            return

        fw_id = self._path_id(r'/api/firmware/images/(\d+)/delete$')
        if fw_id is not None:
            db.delete_firmware_image(fw_id)
            self._send_json({"success": True})
            return

        if path == "/api/firmware/upgrade":
            device_ids = body.get("device_ids", [])
            image_id = body.get("image_id")
            reboot = bool(body.get("reboot", True))
            if not device_ids or not image_id:
                self._send_json({"success": False, "message": "device_ids and image_id required."})
                return
            image = db.get_firmware_image(image_id)
            if not image:
                self._send_json({"success": False, "message": "Firmware image not found."}, 404)
                return

            devices = [db.get_device(did) for did in device_ids]
            devices = [d for d in devices if d]
            job_id = db.create_job("firmware_upgrade", device_ids, {"image_id": image_id, "reboot": reboot})

            def _run_upgrade():
                def _progress(did, status, message):
                    progress = db.get_job(job_id)["progress"] if db.get_job(job_id) else {}
                    progress[str(did)] = {"status": status, "message": message}
                    db.update_job_progress(job_id, progress)
                    log(f"Firmware [{status}] device {did}: {message}", "INFO")

                results = fw.run_fleet_upgrade(devices, image["filepath"], reboot, _resolve_credentials, _progress, max_workers=2)
                db.complete_job(job_id)
                log(f"Firmware upgrade job {job_id} complete.", "PASS")

            executor.submit(_run_upgrade)
            self._send_json({"success": True, "message": "Firmware upgrade started.", "jobId": job_id})
            return

        # ---- Jobs ----
        job_id = self._path_id(r'/api/jobs/(\d+)/cancel$')
        if job_id is not None:
            db.complete_job(job_id, status="cancelled")
            self._send_json({"success": True, "message": "Job cancelled."})
            return

        # ---- Shutdown ----
        if path == "/api/shutdown":
            self._send_json({"success": True, "message": "Shutting down."})
            threading.Thread(target=lambda: (time.sleep(0.5), __import__("os")._exit(0)), daemon=True).start()
            return

        self._send_json({"error": "Not found"}, 404)

    # ---- DELETE routes (mapped to POST with /delete suffix for simplicity) ----
    def do_DELETE(self):
        # Redirect to POST handler - our routes use /delete suffix
        self.do_POST()
