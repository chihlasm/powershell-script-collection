"""
Juniper Console Setup - Browser GUI
====================================
Interactive browser-based tool for provisioning Juniper EX/SRX devices via
serial console cable. Handles factory-default and credentialed devices.

Features:
  - COM port detection and serial connection (pyserial)
  - Factory-default and credential-based login
  - User account creation (any username/class) and password management
  - Management interface IP configuration
  - Firmware upgrade via SCP
  - Running config backup and export
  - Raw Junos command terminal

Usage:
    python juniper_console_setup.py
    python juniper_console_setup.py --port 9090 --com COM5
    python juniper_console_setup.py --no-browser

Requirements:
    pip install pyserial
"""

import argparse
import json
import os
import re
import sys
import threading
import time
import webbrowser
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("ERROR: pyserial is required. Install it with:")
    print("  pip install pyserial")
    sys.exit(1)


# ============================================================================
# GLOBALS
# ============================================================================
ser = None          # serial.Serial instance
is_connected = False
is_logged_in = False
is_config_mode = False
needs_root_password = False
device_info = {"hostname": "", "model": "", "firmware": "", "serial": ""}
session_log = []
serial_lock = threading.Lock()

PROMPT_PATTERN = re.compile(
    r'(login:\s*$|Password:\s*$|root@[\w%-]+[>#]\s*$|[\w.\-]+[>#]\s*$|root@:~#\s*$|\{master:\d+\})',
    re.MULTILINE
)


def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def file_timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H%M%S")


def log(message, level="INFO"):
    entry = {"time": timestamp(), "level": level, "message": message}
    session_log.append(entry)
    colors = {"INFO": "\033[96m", "PASS": "\033[92m", "WARN": "\033[93m", "FAIL": "\033[91m"}
    reset = "\033[0m"
    c = colors.get(level, "")
    print(f"{c}[{level}] {entry['time']}  {message}{reset}")


# ============================================================================
# SERIAL PORT MANAGEMENT
# ============================================================================
def get_available_ports():
    """List available COM ports using pyserial's port enumeration."""
    ports = serial.tools.list_ports.comports()
    return [{"port": p.device, "description": p.description, "hwid": p.hwid} for p in sorted(ports)]


def connect_serial(port_name, baud=9600):
    global ser, is_connected
    try:
        with serial_lock:
            if ser and ser.is_open:
                ser.close()
            ser = serial.Serial(
                port=port_name,
                baudrate=baud,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=3,
                write_timeout=3,
                xonxoff=False,
                rtscts=False,
                dsrdtr=False
            )
            is_connected = True
        log(f"Connected to {port_name} at {baud} baud (8N1)", "PASS")
        return {"success": True, "message": f"Connected to {port_name}"}
    except Exception as e:
        is_connected = False
        log(f"Failed to open {port_name}: {e}", "FAIL")
        return {"success": False, "message": f"Failed to open {port_name}: {e}"}


def disconnect_serial():
    global ser, is_connected, is_logged_in, is_config_mode, needs_root_password, device_info
    with serial_lock:
        if ser and ser.is_open:
            try:
                ser.close()
            except Exception:
                pass
        ser = None
        is_connected = False
        is_logged_in = False
        is_config_mode = False
        needs_root_password = False
        device_info = {"hostname": "", "model": "", "firmware": "", "serial": ""}
    log("Disconnected from serial port.", "INFO")


def send_data(data, newline=True):
    """Send a string over serial."""
    if not ser or not ser.is_open:
        return
    with serial_lock:
        try:
            payload = f"{data}\r" if newline else data
            ser.write(payload.encode("ascii", errors="replace"))
        except Exception as e:
            log(f"Send failed: {e}", "FAIL")


def read_response(timeout_seconds=15, wait_for=""):
    """Read serial data until a prompt is detected or timeout."""
    if not ser or not ser.is_open:
        return ""
    buffer = ""
    deadline = time.time() + timeout_seconds
    wait_re = re.compile(wait_for, re.MULTILINE) if wait_for else None

    while time.time() < deadline:
        with serial_lock:
            try:
                available = ser.in_waiting
                if available > 0:
                    data = ser.read(available).decode("ascii", errors="replace")
                    buffer += data
                else:
                    time.sleep(0.1)
                    continue
            except Exception:
                time.sleep(0.1)
                continue

        # Check for specific wait-for pattern
        if wait_re and wait_re.search(buffer):
            break

        # Check for any known Junos prompt
        if not wait_for and PROMPT_PATTERN.search(buffer):
            time.sleep(0.2)
            with serial_lock:
                try:
                    extra = ser.read(ser.in_waiting).decode("ascii", errors="replace") if ser.in_waiting else ""
                    buffer += extra
                except Exception:
                    pass
            break

        time.sleep(0.1)

    return buffer


def send_command(command, timeout_seconds=15, wait_for=""):
    """Send a Junos CLI command and return the output."""
    send_data(command)
    time.sleep(0.3)
    return read_response(timeout_seconds=timeout_seconds, wait_for=wait_for)


# ============================================================================
# DEVICE OPERATIONS
# ============================================================================
def check_root_password():
    """Check if the device has a root password set. Call after login."""
    global needs_root_password
    log("Checking if root password is configured...", "INFO")
    root_check = send_command("show configuration system root-authentication", timeout_seconds=10)
    if re.search(r'encrypted-password', root_check):
        needs_root_password = False
        log("Root password is set.", "PASS")
    else:
        needs_root_password = True
        log("Root password is NOT set. Must be configured before any commit.", "WARN")
    return needs_root_password


def _enter_cli_from_shell(response_text):
    """If we're at a root shell prompt, enter CLI. Returns True if we entered CLI."""
    if re.search(r'root@[\w%-]*:~#|root@:~#|root@[\w%-]*%', response_text):
        send_command("cli")
        send_command("set cli screen-length 0")
        return True
    return False


def _finalize_login(message, factory_default=False):
    """After successful login, check root password status and build response."""
    global is_logged_in
    is_logged_in = True
    root_needed = check_root_password()
    result = {"success": True, "message": message, "needsRootPassword": root_needed}
    if factory_default:
        result["factoryDefault"] = True
    return result


def do_login(username="", password="", try_factory=False):
    global is_logged_in, is_config_mode

    # Wake console
    send_data("")
    time.sleep(0.5)
    send_data("")
    time.sleep(0.5)
    response = read_response(timeout_seconds=5)

    # Already at operational CLI prompt (hostname>)
    if re.search(r'[\w.\-]+>\s*$', response):
        send_command("set cli screen-length 0")
        log("Already at operational CLI prompt.", "PASS")
        return _finalize_login("Already logged in at CLI prompt.")

    # Already in configuration mode (hostname#) but NOT root shell
    if re.search(r'[\w.\-]+#\s*$', response) and not re.search(r'root@[\w%-]*:~#|root@:~#', response):
        is_config_mode = True
        log("Already in configuration mode.", "PASS")
        return _finalize_login("Already in configuration mode.")

    # At root shell (factory default - already past login)
    if _enter_cli_from_shell(response):
        log("At root shell. Entered CLI.", "PASS")
        return _finalize_login("Logged in (root shell, entered CLI).", factory_default=True)

    # At login prompt
    if re.search(r'login:\s*$', response):

        # --- Try factory-default: root with no password ---
        if try_factory:
            log("Trying factory-default login (root / no password)...", "INFO")
            send_data("root")
            time.sleep(1)
            after_user = read_response(timeout_seconds=5)

            # Case 1: Device asks for password
            if re.search(r'Password:\s*$', after_user):
                send_data("")  # empty password
                time.sleep(1)
                result = read_response(timeout_seconds=5)

                if re.search(r'Login incorrect|login:\s*$', result):
                    log("Factory-default login failed. Device has a password.", "WARN")
                    return {"success": False, "message": "Factory-default login failed. Device has credentials set.", "needsCredentials": True}

                # Got past password - might be shell or CLI
                if _enter_cli_from_shell(result):
                    pass  # entered CLI from shell
                elif re.search(r'[\w.\-]+>\s*$', result):
                    send_command("set cli screen-length 0")
                log("Logged in as root (factory default, empty password).", "PASS")
                return _finalize_login("Logged in as root (factory default).", factory_default=True)

            # Case 2: No password prompt - went straight to shell or CLI
            elif _enter_cli_from_shell(after_user):
                log("Logged in as root (no password prompt).", "PASS")
                return _finalize_login("Logged in as root (no password required).", factory_default=True)

            elif re.search(r'[\w.\-]+>\s*$', after_user):
                send_command("set cli screen-length 0")
                log("Logged in as root (no password, at CLI).", "PASS")
                return _finalize_login("Logged in as root (no password required).", factory_default=True)

            else:
                # Factory default didn't clearly work - fall through to manual
                log("Factory-default login gave unexpected response, trying manual.", "WARN")

        # --- Manual credentials ---
        if not username:
            return {"success": False, "message": "At login prompt. Provide credentials.", "needsCredentials": True}

        log(f"Logging in as {username}...", "INFO")

        # Make sure we're at a login prompt (factory attempt may have left us elsewhere)
        wake = read_response(timeout_seconds=2)
        if not re.search(r'login:\s*$', wake):
            # Send enter to get back to login prompt
            send_data("")
            time.sleep(0.5)
            send_data("")
            time.sleep(0.5)
            read_response(timeout_seconds=3)

        send_data(username)
        time.sleep(0.5)
        pass_prompt = read_response(timeout_seconds=5)

        if re.search(r'Password:\s*$', pass_prompt):
            send_data(password)
            time.sleep(1)
            result = read_response(timeout_seconds=10)

            if re.search(r'Login incorrect|login:\s*$', result):
                log(f"Login failed for {username}.", "FAIL")
                return {"success": False, "message": "Login failed. Check credentials."}

            # Got in - might be shell or CLI
            if _enter_cli_from_shell(result):
                pass
            elif re.search(r'[\w.\-]+>\s*$', result):
                send_command("set cli screen-length 0")
            log(f"Logged in as {username}.", "PASS")
            return _finalize_login(f"Logged in as {username}.")

        # No password prompt - maybe went straight to shell
        elif _enter_cli_from_shell(pass_prompt):
            log(f"Logged in as {username} (no password prompt).", "PASS")
            return _finalize_login(f"Logged in as {username}.")

        return {"success": False, "message": "Unexpected response during login."}

    log("Console in unrecognized state.", "WARN")
    return {"success": False, "message": "Unrecognized console state. Try pressing Enter on the device first.", "raw": response}


def set_root_password(root_password):
    """Standalone root password setter - can be called independently of account creation."""
    global is_config_mode, needs_root_password

    if not root_password or len(root_password) < 6:
        return {"success": False, "message": "Root password must be at least 6 characters."}

    log("Setting root password...", "INFO")

    # Enter config mode if not already there
    if not is_config_mode:
        send_command("configure", timeout_seconds=5)
        is_config_mode = True

    send_data("set system root-authentication plain-text-password")
    time.sleep(0.5)
    read_response(timeout_seconds=5, wait_for="New password:")
    send_data(root_password)
    time.sleep(0.5)
    read_response(timeout_seconds=5, wait_for="Retype new password:")
    send_data(root_password)
    time.sleep(0.5)
    read_response(timeout_seconds=3)

    log("Committing root password...", "INFO")
    commit_result = send_command("commit", timeout_seconds=120, wait_for=r"(?i)(commit complete|commit confirmed|error:|error\b|failed)")
    log(f"Commit raw output: {repr(commit_result[:200])}", "INFO")

    send_command("exit")
    is_config_mode = False

    if "commit complete" in commit_result.lower():
        needs_root_password = False
        log("Root password set and committed successfully.", "PASS")
        return {"success": True, "message": "Root password set successfully."}
    else:
        log(f"Root password commit may have failed. Raw: {repr(commit_result[:300])}", "WARN")
        return {"success": False, "message": "Commit returned unexpected output.", "raw": commit_result}


def get_device_info():
    global device_info, is_config_mode

    if is_config_mode:
        send_command("exit")
        is_config_mode = False

    version_output = send_command("show version", timeout_seconds=10)

    m = re.search(r'Hostname:\s+(\S+)', version_output)
    if m:
        device_info["hostname"] = m.group(1)

    m = re.search(r'Model:\s+(\S+)', version_output)
    if m:
        device_info["model"] = m.group(1)

    m = re.search(r'Junos:\s+(\S+)', version_output)
    if m:
        device_info["firmware"] = m.group(1)
    else:
        m = re.search(r'JUNOS\s+\S+\s+\[(\S+)\]', version_output)
        if m:
            device_info["firmware"] = m.group(1)

    chassis_output = send_command("show chassis hardware | match Chassis", timeout_seconds=10)
    m = re.search(r'Chassis\s+\S+\s+\S+\s+(\S+)', chassis_output)
    if m:
        device_info["serial"] = m.group(1)
    else:
        m = re.search(r'Chassis\s+(\S+)', chassis_output)
        if m:
            device_info["serial"] = m.group(1)

    log(f"Device: {device_info['hostname']} / {device_info['model']} / Junos {device_info['firmware']} / SN {device_info['serial']}", "PASS")
    return {
        "success": True,
        "hostname": device_info["hostname"],
        "model": device_info["model"],
        "firmware": device_info["firmware"],
        "serial": device_info["serial"],
        "raw": version_output
    }


def get_user_list():
    """Retrieve the list of configured login users from the device."""
    global is_config_mode
    if is_config_mode:
        send_command("exit")
        is_config_mode = False

    log("Retrieving user list...", "INFO")

    users = {}

    # Method 1: Try "display set" format - gives lines like:
    #   set system login user vc3admin class super-user
    output_set = send_command("show configuration system login user | display set", timeout_seconds=10)
    for line in output_set.splitlines():
        m = re.search(r'set system login user (\S+) class (\S+)', line.strip())
        if m:
            users[m.group(1)] = {"username": m.group(1), "class": m.group(2)}

    # Method 2: If display set didn't work, try hierarchical format - gives blocks like:
    #   user vc3admin {
    #       class super-user;
    if not users:
        output_hier = send_command("show configuration system login", timeout_seconds=10)
        current_user = None
        for line in output_hier.splitlines():
            m = re.match(r'\s*user\s+(\S+)\s*\{', line)
            if m:
                current_user = m.group(1)
                users[current_user] = {"username": current_user, "class": "unknown"}
            elif current_user:
                m = re.match(r'\s*class\s+(\S+);', line)
                if m:
                    users[current_user]["class"] = m.group(1)
                if re.match(r'\s*\}', line):
                    current_user = None

    user_list = sorted(users.values(), key=lambda u: u["username"])
    log(f"Found {len(user_list)} user(s): {', '.join(u['username'] for u in user_list) if user_list else 'none'}", "PASS" if user_list else "WARN")
    return {"success": True, "users": user_list, "raw": output_set}


def create_user_account(username, password, user_class="super-user"):
    """Create a new user account or reset an existing user's password."""
    global is_config_mode, needs_root_password

    if needs_root_password:
        return {
            "success": False,
            "message": "Root password must be set first. Go to the Login page and set it before creating accounts.",
            "needsRootPassword": True
        }

    log(f"Provisioning user '{username}' (class: {user_class})...", "INFO")

    existing_check = send_command(f"show configuration system login user {username}", timeout_seconds=10)
    already_exists = bool(re.search(r'class |encrypted-password', existing_check))

    # Enter config mode
    send_command("configure", timeout_seconds=5)
    is_config_mode = True

    action = "Resetting password for" if already_exists else "Creating"
    log(f"{action} user '{username}' ({user_class})...", "INFO")
    send_data(f"set system login user {username} class {user_class} authentication plain-text-password")
    time.sleep(0.5)
    read_response(timeout_seconds=5, wait_for="New password:")
    send_data(password)
    time.sleep(0.5)
    read_response(timeout_seconds=5, wait_for="Retype new password:")
    send_data(password)
    time.sleep(0.5)
    read_response(timeout_seconds=3)

    # Commit
    log("Committing configuration...", "INFO")
    commit_result = send_command("commit", timeout_seconds=120, wait_for=r"(?i)(commit complete|commit confirmed|error:|error\b|failed)")
    log(f"Commit raw output: {repr(commit_result[:200])}", "INFO")

    send_command("exit")
    is_config_mode = False

    if "commit complete" in commit_result.lower():
        action_past = "password reset" if already_exists else "created"
        log(f"User '{username}' {action_past} successfully.", "PASS")
        return {"success": True, "message": f"User '{username}' {action_past} successfully.", "alreadyExisted": already_exists}
    else:
        log(f"Commit may have failed. Raw: {repr(commit_result[:300])}", "WARN")
        return {"success": False, "message": "Commit returned unexpected output. Check the console log for details.", "raw": commit_result}


def update_user_password(username, password):
    """Update the password for an existing user."""
    global is_config_mode, needs_root_password

    if needs_root_password:
        return {
            "success": False,
            "message": "Root password must be set first.",
            "needsRootPassword": True
        }

    log(f"Updating password for '{username}'...", "INFO")

    send_command("configure", timeout_seconds=5)
    is_config_mode = True

    send_data(f"set system login user {username} authentication plain-text-password")
    time.sleep(0.5)
    read_response(timeout_seconds=5, wait_for="New password:")
    send_data(password)
    time.sleep(0.5)
    read_response(timeout_seconds=5, wait_for="Retype new password:")
    send_data(password)
    time.sleep(0.5)
    read_response(timeout_seconds=3)

    log("Committing password change...", "INFO")
    commit_result = send_command("commit", timeout_seconds=120, wait_for=r"(?i)(commit complete|commit confirmed|error:|error\b|failed)")
    log(f"Commit raw output: {repr(commit_result[:200])}", "INFO")

    send_command("exit")
    is_config_mode = False

    if "commit complete" in commit_result.lower():
        log(f"Password updated for '{username}'.", "PASS")
        return {"success": True, "message": f"Password updated for '{username}'."}
    else:
        log(f"Commit may have failed. Raw: {repr(commit_result[:300])}", "WARN")
        return {"success": False, "message": "Commit returned unexpected output. Check console log.", "raw": commit_result}


def set_management_ip(ip_address, gateway=None, interface=None):
    global is_config_mode

    if not interface:
        info_output = send_command("show version", timeout_seconds=10)
        if re.search(r'EX\d+', info_output):
            interface = "vme"
        elif re.search(r'SRX\d+', info_output):
            interface = "fxp0"
        else:
            interface = "me0"

    log(f"Configuring {interface} with {ip_address}...", "INFO")
    send_command("configure", timeout_seconds=5)
    is_config_mode = True

    send_command(f"set interfaces {interface} unit 0 family inet address {ip_address}", timeout_seconds=5)

    if gateway and gateway.strip():
        send_command(f"set routing-options static route 0.0.0.0/0 next-hop {gateway.strip()}", timeout_seconds=5)

    commit_result = send_command("commit", timeout_seconds=120, wait_for=r"(?i)(commit complete|commit confirmed|error:|error\b|failed)")
    log(f"Commit raw output: {repr(commit_result[:200])}", "INFO")
    send_command("exit")
    is_config_mode = False

    if "commit complete" in commit_result.lower():
        ip_only = ip_address.split("/")[0]
        log(f"Management interface {interface} configured with {ip_address}. Device reachable at {ip_only}.", "PASS")
        return {"success": True, "message": f"Management IP configured. Device reachable at {ip_only}.", "interface": interface, "ip": ip_only}
    else:
        log(f"Commit may have failed for management IP. Raw: {repr(commit_result[:300])}", "WARN")
        return {"success": False, "message": "Commit returned unexpected output.", "raw": commit_result}


def enable_netconf(enable_ssh=True, enable_netconf_ssh=True, enable_rest=False):
    """Enable NETCONF/SSH/REST services so the device can be managed remotely."""
    global is_config_mode, needs_root_password

    if needs_root_password:
        return {"success": False, "message": "Root password must be set first."}

    log("Enabling remote management services...", "INFO")
    send_command("configure", timeout_seconds=5)
    is_config_mode = True

    services = []
    if enable_ssh:
        send_command("set system services ssh", timeout_seconds=5)
        services.append("SSH")
    if enable_netconf_ssh:
        send_command("set system services netconf ssh", timeout_seconds=5)
        services.append("NETCONF over SSH (port 830)")
    if enable_rest:
        send_command("set system services rest http", timeout_seconds=5)
        send_command("set system services rest enable-explorer", timeout_seconds=5)
        services.append("REST API")

    log("Committing remote access configuration...", "INFO")
    commit_result = send_command("commit", timeout_seconds=120, wait_for=r"(?i)(commit complete|commit confirmed|error:|error\b|failed)")
    log(f"Commit raw output: {repr(commit_result[:200])}", "INFO")

    send_command("exit")
    is_config_mode = False

    if "commit complete" in commit_result.lower():
        svc_list = ", ".join(services)
        log(f"Remote access enabled: {svc_list}", "PASS")
        return {"success": True, "message": f"Enabled: {svc_list}. Device is now manageable via NETCONF."}
    else:
        log(f"Commit may have failed for remote access. Raw: {repr(commit_result[:300])}", "WARN")
        return {"success": False, "message": "Commit returned unexpected output. Check console log.", "raw": commit_result}


def scp_firmware(laptop_ip, scp_user, scp_path):
    filename = scp_path.split("/")[-1]
    scp_cmd = f"scp {scp_user}@{laptop_ip}:{scp_path} /var/tmp/{filename}"
    log(f"Starting SCP: {scp_cmd}", "INFO")
    send_data(scp_cmd)
    return {"success": True, "message": "SCP command sent. Watch the log for host-key/password prompts.", "command": scp_cmd, "remoteFile": f"/var/tmp/{filename}"}


def install_firmware(image_path, reboot=False):
    cmd = f"request system software add {image_path} no-validate"
    if reboot:
        cmd += " reboot"
    log(f"Running: {cmd}", "WARN")
    send_data(cmd)
    return {"success": True, "message": "Firmware install command sent. This takes 10-30 minutes.", "command": cmd, "willReboot": reboot}


def get_running_config():
    global is_config_mode
    if is_config_mode:
        send_command("exit")
        is_config_mode = False
    send_command("set cli screen-length 0")
    config = send_command("show configuration", timeout_seconds=30)
    log("Running configuration retrieved.", "PASS")
    return config


def load_config(config_text, mode="merge", confirm_minutes=5):
    """Load a configuration onto the device via serial console.

    mode: 'merge' (additive), 'override' (full replace), or 'replace' (replace matching sections)
    confirm_minutes: auto-rollback timeout (0 to skip commit confirmed)
    """
    global is_config_mode, needs_root_password

    if needs_root_password:
        return {"success": False, "message": "Root password must be set first."}

    if not config_text or not config_text.strip():
        return {"success": False, "message": "No configuration provided."}

    # Detect format: 'set' commands vs hierarchical
    lines = [l for l in config_text.strip().splitlines() if l.strip() and not l.strip().startswith('#')]
    is_set_format = all(l.strip().startswith(('set ', 'delete ', 'deactivate ', 'activate ')) for l in lines[:10])
    config_format = "set" if is_set_format else "text"

    log(f"Loading config ({len(lines)} lines, format: {config_format}, mode: {mode})...", "INFO")

    # Enter config mode
    send_command("configure", timeout_seconds=5)
    is_config_mode = True

    # Load the config line by line for set format, or as a block for hierarchical
    errors = []
    if config_format == "set":
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            result = send_command(line, timeout_seconds=10)
            # Check for errors in the response
            if result and ('syntax error' in result.lower() or 'unknown command' in result.lower() or 'error' in result.lower()):
                errors.append(f"Line {i+1}: {line} -> {result.strip()}")
                log(f"Config error on line {i+1}: {result.strip()}", "WARN")
    else:
        # Hierarchical format: use load override/merge/replace
        load_cmd = f"load {mode} terminal"
        log(f"Running: {load_cmd}", "INFO")
        send_data(load_cmd)
        time.sleep(0.5)
        read_response(timeout_seconds=3)  # Wait for the prompt to accept input

        # Send config block line by line
        config_lines = config_text.strip().splitlines()
        log(f"Sending {len(config_lines)} lines to device...", "INFO")
        for i, line in enumerate(config_lines):
            send_data(line)
            # Small delay every 50 lines to avoid overwhelming the serial buffer
            if i % 50 == 49:
                time.sleep(0.2)
            else:
                time.sleep(0.02)

        # Send Ctrl+D to end the terminal input
        log("Sending end-of-input (Ctrl+D)...", "INFO")
        time.sleep(1)
        send_data("\x04", newline=False)
        time.sleep(2)
        # Wait for the device to finish processing the load
        load_result = read_response(timeout_seconds=30)
        log(f"Load result: {repr(load_result[:200])}", "INFO")
        # Check for actual load errors (not just the word 'error' in config text)
        if load_result and re.search(r'(syntax error|load complete.*error|invalid value)', load_result, re.IGNORECASE):
            errors.append(load_result.strip())

    if errors:
        log(f"Config load had {len(errors)} error(s). Rolling back.", "FAIL")
        send_command("rollback 0", timeout_seconds=5)
        send_command("exit", timeout_seconds=3)
        is_config_mode = False
        return {
            "success": False,
            "message": f"Config load failed with {len(errors)} error(s). Changes rolled back.",
            "errors": errors
        }

    # Show the diff before committing
    log("Generating config diff...", "INFO")
    diff_output = send_command("show | compare", timeout_seconds=30)
    log(f"Config diff: {len(diff_output)} chars", "INFO")

    # Commit with confirmed safety net
    if confirm_minutes > 0:
        commit_cmd = f"commit confirmed {confirm_minutes}"
        log(f"Using {commit_cmd} (auto-rollback in {confirm_minutes} min if not confirmed)...", "WARN")
    else:
        commit_cmd = "commit"

    log(f"Sending: {commit_cmd}", "INFO")
    send_data(commit_cmd)
    time.sleep(1)
    # Commits on large configs can take several minutes - wait patiently
    # Only match on the config mode prompt returning (hostname#) which means the commit finished
    commit_result = read_response(timeout_seconds=300, wait_for=r"(?i)(commit complete|#\s*$)")
    log(f"Commit raw output ({len(commit_result)} chars): {repr(commit_result[:300])}", "INFO")

    if "commit complete" not in commit_result.lower():
        # Check if we got back to a prompt (commit might have succeeded without the exact text)
        if re.search(r'#\s*$', commit_result):
            log("Commit returned to prompt without 'commit complete' text. Checking status...", "WARN")
            # Verify by checking if we're still in config mode
            check = send_command("show | compare", timeout_seconds=10)
            if not check.strip() or len(check.strip()) < 20:
                log("No pending changes - commit likely succeeded.", "PASS")
            else:
                log("Pending changes still exist - commit may have failed.", "FAIL")
                send_command("rollback 0", timeout_seconds=5)
                send_command("exit", timeout_seconds=3)
                is_config_mode = False
                return {"success": False, "message": "Commit may have failed. Changes rolled back.", "raw": commit_result}
        else:
            log("Commit did not complete within timeout.", "FAIL")
            send_command("rollback 0", timeout_seconds=5)
            send_command("exit", timeout_seconds=3)
            is_config_mode = False
            return {"success": False, "message": "Commit timed out. Changes rolled back.", "raw": commit_result}

    # If commit confirmed, now confirm it
    if confirm_minutes > 0:
        log("Confirming commit...", "INFO")
        time.sleep(2)
        send_data("commit")
        time.sleep(1)
        confirm_result = read_response(timeout_seconds=300, wait_for=r"(?i)(commit complete|#\s*$)")
        log(f"Confirm raw output: {repr(confirm_result[:200])}", "INFO")
        if "commit complete" in confirm_result.lower():
            log("Commit confirmed.", "PASS")
        else:
            log("Commit confirmation returned to prompt (likely succeeded).", "PASS")

    send_command("exit", timeout_seconds=3)
    is_config_mode = False

    log(f"Configuration loaded successfully ({len(lines)} lines, mode: {mode}).", "PASS")
    return {
        "success": True,
        "message": f"Configuration loaded successfully ({len(lines)} lines, mode: {mode}).",
        "diff": diff_output,
        "lines": len(lines),
        "format": config_format,
    }


def raw_command(command):
    log(f"CMD> {command}", "INFO")
    return send_command(command, timeout_seconds=15)


# ============================================================================
# HTML FRONTEND
# ============================================================================
HTML_CONTENT = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Juniper Console Setup</title>
<style>
:root {
    --bg: #0f172a;
    --bg-card: #1e293b;
    --bg-card-hover: #263348;
    --bg-input: #334155;
    --bg-sidebar: #0c1322;
    --text: #e2e8f0;
    --text-muted: #94a3b8;
    --text-heading: #f1f5f9;
    --border: #334155;
    --accent: #38bdf8;
    --accent-hover: #7dd3fc;
    --accent-dim: rgba(56, 189, 248, 0.15);
    --success: #34d399;
    --success-dim: rgba(52, 211, 153, 0.15);
    --warning: #fbbf24;
    --warning-dim: rgba(251, 191, 36, 0.15);
    --danger: #f87171;
    --danger-dim: rgba(248, 113, 113, 0.15);
    --radius: 8px;
    --shadow: 0 1px 3px rgba(0,0,0,0.4);
    --font-mono: 'Cascadia Code', 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
}
[data-theme="light"] {
    --bg: #f1f5f9;
    --bg-card: #ffffff;
    --bg-card-hover: #f8fafc;
    --bg-input: #e2e8f0;
    --bg-sidebar: #e2e8f0;
    --text: #1e293b;
    --text-muted: #64748b;
    --text-heading: #0f172a;
    --border: #cbd5e1;
    --accent: #0284c7;
    --accent-hover: #0369a1;
    --accent-dim: rgba(2, 132, 199, 0.1);
    --success: #059669;
    --success-dim: rgba(5, 150, 105, 0.1);
    --warning: #d97706;
    --warning-dim: rgba(217, 119, 6, 0.1);
    --danger: #dc2626;
    --danger-dim: rgba(220, 38, 38, 0.1);
    --shadow: 0 1px 3px rgba(0,0,0,0.1);
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg); color: var(--text);
    height: 100vh; display: flex; flex-direction: column; overflow: hidden;
}
.topbar {
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 20px; height: 56px; background: var(--bg-sidebar);
    border-bottom: 1px solid var(--border); flex-shrink: 0;
}
.topbar-left { display: flex; align-items: center; gap: 14px; }
.topbar-logo { font-size: 18px; font-weight: 700; color: var(--accent); letter-spacing: -0.5px; }
.topbar-logo span { color: var(--text-muted); font-weight: 400; font-size: 13px; margin-left: 6px; }
.topbar-right { display: flex; align-items: center; gap: 12px; }
.status-badge {
    display: flex; align-items: center; gap: 6px; padding: 4px 12px;
    border-radius: 20px; font-size: 12px; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.5px;
}
.status-badge.disconnected { background: var(--danger-dim); color: var(--danger); }
.status-badge.connected    { background: var(--warning-dim); color: var(--warning); }
.status-badge.logged-in    { background: var(--success-dim); color: var(--success); }
.status-dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; animation: pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
.theme-toggle {
    background: var(--bg-input); border: 1px solid var(--border); color: var(--text);
    width: 36px; height: 36px; border-radius: 50%; cursor: pointer; font-size: 16px;
    display: flex; align-items: center; justify-content: center; transition: all 0.2s;
}
.theme-toggle:hover { background: var(--bg-card-hover); border-color: var(--accent); }
.btn-shutdown {
    background: transparent; border: 1px solid var(--border); color: var(--text-muted);
    padding: 6px 12px; border-radius: var(--radius); cursor: pointer; font-size: 12px; transition: all 0.2s;
}
.btn-shutdown:hover { border-color: var(--danger); color: var(--danger); }
.main-layout { display: flex; flex: 1; overflow: hidden; }
.sidebar {
    width: 220px; background: var(--bg-sidebar); border-right: 1px solid var(--border);
    display: flex; flex-direction: column; flex-shrink: 0; padding: 12px 0;
}
.nav-item {
    display: flex; align-items: center; gap: 10px; padding: 10px 20px;
    color: var(--text-muted); cursor: pointer; font-size: 13px; font-weight: 500;
    transition: all 0.15s; border-left: 3px solid transparent; user-select: none;
}
.nav-item:hover { color: var(--text); background: var(--bg-card); }
.nav-item.active { color: var(--accent); background: var(--accent-dim); border-left-color: var(--accent); }
.nav-item.disabled { opacity: 0.35; pointer-events: none; }
.nav-icon { font-size: 16px; width: 20px; text-align: center; }
.nav-label { flex: 1; }
.nav-step {
    font-size: 10px; background: var(--bg-input); color: var(--text-muted);
    width: 20px; height: 20px; border-radius: 50%; display: flex;
    align-items: center; justify-content: center; font-weight: 700;
}
.nav-item.done .nav-step { background: var(--success-dim); color: var(--success); }
.nav-divider { height: 1px; background: var(--border); margin: 8px 20px; }
.sidebar-footer {
    margin-top: auto; padding: 12px 20px; font-size: 11px;
    color: var(--text-muted); border-top: 1px solid var(--border);
}
.content-area { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
.content-main { flex: 1; overflow-y: auto; padding: 24px; }
.page { display: none; }
.page.active { display: block; }
.page-title { font-size: 20px; font-weight: 700; color: var(--text-heading); margin-bottom: 4px; }
.page-subtitle { font-size: 13px; color: var(--text-muted); margin-bottom: 20px; }
.card {
    background: var(--bg-card); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 20px; margin-bottom: 16px; box-shadow: var(--shadow);
}
.card-title { font-size: 14px; font-weight: 600; color: var(--text-heading); margin-bottom: 12px; }
.info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; }
.info-item label {
    display: block; font-size: 11px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 4px;
}
.info-item .value { font-size: 16px; font-weight: 600; color: var(--text-heading); font-family: var(--font-mono); }
.info-item .value.empty { color: var(--text-muted); font-style: italic; font-weight: 400; }
.form-group { margin-bottom: 16px; }
.form-group label { display: block; font-size: 13px; font-weight: 500; color: var(--text); margin-bottom: 6px; }
.form-group .hint { font-size: 11px; color: var(--text-muted); margin-top: 4px; }
input[type="text"], input[type="password"], select, textarea {
    width: 100%; padding: 9px 12px; background: var(--bg-input);
    border: 1px solid var(--border); border-radius: 6px; color: var(--text);
    font-size: 14px; font-family: inherit; outline: none; transition: border-color 0.2s;
}
input:focus, select:focus, textarea:focus { border-color: var(--accent); }
input::placeholder, textarea::placeholder { color: var(--text-muted); }
textarea { resize: vertical; font-family: var(--font-mono); font-size: 13px; }
.form-row { display: flex; gap: 12px; }
.form-row .form-group { flex: 1; }
.checkbox-group { display: flex; align-items: center; gap: 8px; cursor: pointer; font-size: 13px; }
.checkbox-group input[type="checkbox"] { width: auto; cursor: pointer; }
.btn {
    display: inline-flex; align-items: center; gap: 6px; padding: 9px 18px;
    border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer;
    border: 1px solid transparent; transition: all 0.2s; font-family: inherit;
}
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover:not(:disabled) { background: var(--accent-hover); }
.btn-success { background: var(--success); color: #fff; }
.btn-success:hover:not(:disabled) { filter: brightness(1.1); }
.btn-danger  { background: var(--danger); color: #fff; }
.btn-danger:hover:not(:disabled) { filter: brightness(1.1); }
.btn-outline { background: transparent; border-color: var(--border); color: var(--text); }
.btn-outline:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
.btn-group { display: flex; gap: 8px; margin-top: 16px; flex-wrap: wrap; }
.alert {
    padding: 12px 16px; border-radius: 6px; font-size: 13px; margin-bottom: 16px;
    display: none; align-items: flex-start; gap: 8px; line-height: 1.5;
}
.alert.show { display: flex; }
.alert-success { background: var(--success-dim); color: var(--success); border: 1px solid var(--success); }
.alert-danger  { background: var(--danger-dim); color: var(--danger); border: 1px solid var(--danger); }
.alert-warning { background: var(--warning-dim); color: var(--warning); border: 1px solid var(--warning); }
.alert-info    { background: var(--accent-dim); color: var(--accent); border: 1px solid var(--accent); }
.log-panel {
    height: 200px; min-height: 100px; background: #0a0e17;
    border-top: 1px solid var(--border); display: flex; flex-direction: column; flex-shrink: 0;
}
[data-theme="light"] .log-panel { background: #1e293b; }
.log-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 6px 16px; background: rgba(0,0,0,0.2); border-bottom: 1px solid rgba(255,255,255,0.06);
}
.log-header-title { font-size: 11px; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; }
.log-body {
    flex: 1; overflow-y: auto; padding: 8px 16px; font-family: var(--font-mono);
    font-size: 12px; line-height: 1.6; color: #cbd5e1;
}
.log-entry { white-space: pre-wrap; word-break: break-all; }
.log-entry.INFO { color: #67e8f9; }
.log-entry.PASS { color: #6ee7b7; }
.log-entry.WARN { color: #fcd34d; }
.log-entry.FAIL { color: #fca5a5; }
.log-resize { height: 4px; background: var(--border); cursor: ns-resize; }
.log-resize:hover { background: var(--accent); }
.terminal-wrap { background: #0a0e17; border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
[data-theme="light"] .terminal-wrap { background: #1e293b; }
.terminal-output {
    height: 300px; overflow-y: auto; padding: 12px 16px; font-family: var(--font-mono);
    font-size: 13px; line-height: 1.5; color: #e2e8f0; white-space: pre-wrap; word-break: break-all;
}
.terminal-input-row { display: flex; border-top: 1px solid rgba(255,255,255,0.06); }
.terminal-prompt {
    padding: 10px 12px; color: var(--accent); font-family: var(--font-mono);
    font-size: 13px; font-weight: 700; user-select: none;
}
.terminal-input {
    flex: 1; background: transparent; border: none; color: #e2e8f0;
    font-family: var(--font-mono); font-size: 13px; padding: 10px 0; outline: none;
}
.progress-bar { height: 4px; background: var(--bg-input); border-radius: 2px; overflow: hidden; margin: 12px 0; }
.progress-fill { height: 100%; background: var(--accent); border-radius: 2px; width: 0%; transition: width 0.3s; }
.progress-fill.indeterminate { width: 30%; animation: indeterminate 1.5s infinite ease-in-out; }
@keyframes indeterminate { 0%{margin-left:0%} 50%{margin-left:70%} 100%{margin-left:0%} }
.config-viewer {
    background: #0a0e17; border: 1px solid var(--border); border-radius: var(--radius);
    padding: 16px; font-family: var(--font-mono); font-size: 13px; line-height: 1.5;
    color: #e2e8f0; max-height: 500px; overflow-y: auto; white-space: pre-wrap; word-break: break-all;
}
[data-theme="light"] .config-viewer { background: #1e293b; }
.spinner {
    display: inline-block; width: 14px; height: 14px;
    border: 2px solid rgba(255,255,255,0.3); border-top-color: #fff;
    border-radius: 50%; animation: spin 0.6s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
.btn .spinner { width: 12px; height: 12px; }
.port-desc { font-size: 11px; color: var(--text-muted); }
</style>
</head>
<body>
<div class="topbar">
    <div class="topbar-left">
        <div class="topbar-logo">Juniper Console Setup <span>VC3 Engineering</span></div>
    </div>
    <div class="topbar-right">
        <div id="statusBadge" class="status-badge disconnected">
            <span class="status-dot"></span>
            <span id="statusText">Disconnected</span>
        </div>
        <button class="theme-toggle" onclick="toggleTheme()" title="Toggle theme">&#9681;</button>
        <button class="btn-shutdown" onclick="shutdown()">Shut Down</button>
    </div>
</div>
<div class="main-layout">
    <div class="sidebar">
        <div class="nav-item active" data-page="connect" onclick="showPage('connect')">
            <span class="nav-icon">&#9986;</span><span class="nav-label">Connect</span><span class="nav-step">1</span>
        </div>
        <div class="nav-item disabled" data-page="login" onclick="showPage('login')">
            <span class="nav-icon">&#128274;</span><span class="nav-label">Login</span><span class="nav-step">2</span>
        </div>
        <div class="nav-item disabled" data-page="info" onclick="showPage('info')">
            <span class="nav-icon">&#8505;</span><span class="nav-label">Device Info</span><span class="nav-step">3</span>
        </div>
        <div class="nav-item disabled" data-page="account" onclick="showPage('account')">
            <span class="nav-icon">&#128100;</span><span class="nav-label">User Account</span><span class="nav-step">4</span>
        </div>
        <div class="nav-item disabled" data-page="network" onclick="showPage('network')">
            <span class="nav-icon">&#127760;</span><span class="nav-label">Management IP</span><span class="nav-step">5</span>
        </div>
        <div class="nav-item disabled" data-page="firmware" onclick="showPage('firmware')">
            <span class="nav-icon">&#11014;</span><span class="nav-label">Firmware</span><span class="nav-step">6</span>
        </div>
        <div class="nav-divider"></div>
        <div class="nav-item disabled" data-page="config" onclick="showPage('config')">
            <span class="nav-icon">&#128196;</span><span class="nav-label">Config</span>
        </div>
        <div class="nav-item disabled" data-page="terminal" onclick="showPage('terminal')">
            <span class="nav-icon">&#62;</span><span class="nav-label">Terminal</span>
        </div>
        <div class="sidebar-footer">COM: <span id="sidebarPort">--</span><br>Baud: <span id="sidebarBaud">9600</span></div>
    </div>
    <div class="content-area">
        <div class="content-main">

            <!-- CONNECT -->
            <div id="page-connect" class="page active">
                <div class="page-title">Connect to Device</div>
                <div class="page-subtitle">Select a COM port and connect to the Juniper console.</div>
                <div class="card">
                    <div class="card-title">Serial Connection</div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>COM Port</label>
                            <div style="display:flex;gap:8px;">
                                <select id="comPortSelect" style="flex:1;"><option value="">-- Scanning... --</option></select>
                                <button class="btn btn-outline" onclick="refreshPorts()">Refresh</button>
                            </div>
                            <div id="portDescription" class="port-desc" style="margin-top:4px;"></div>
                        </div>
                        <div class="form-group">
                            <label>Baud Rate</label>
                            <select id="baudSelect">
                                <option value="9600" selected>9600 (standard)</option>
                                <option value="19200">19200</option>
                                <option value="38400">38400</option>
                                <option value="57600">57600</option>
                                <option value="115200">115200</option>
                            </select>
                        </div>
                    </div>
                    <div id="connectAlert" class="alert"></div>
                    <div class="btn-group">
                        <button id="btnConnect" class="btn btn-primary" onclick="connectPort()">Connect</button>
                        <button id="btnDisconnect" class="btn btn-danger" onclick="disconnectPort()" style="display:none;">Disconnect</button>
                    </div>
                </div>
            </div>

            <!-- LOGIN -->
            <div id="page-login" class="page">
                <div class="page-title">Login to Device</div>
                <div class="page-subtitle">Authenticate with the Juniper device. Factory-default devices use root with no password.</div>
                <div class="card">
                    <div class="card-title">Authentication</div>
                    <div id="loginAlert" class="alert"></div>
                    <div class="form-group">
                        <label class="checkbox-group">
                            <input type="checkbox" id="tryFactory" checked>
                            Try factory-default first (root / no password)
                        </label>
                    </div>
                    <div id="credentialsSection">
                        <div class="form-row">
                            <div class="form-group"><label>Username</label><input type="text" id="loginUser" placeholder="root"></div>
                            <div class="form-group"><label>Password</label><input type="password" id="loginPass" placeholder="Enter password (leave blank for factory-default)"></div>
                        </div>
                    </div>
                    <div class="btn-group"><button id="btnLogin" class="btn btn-primary" onclick="doLogin()">Login</button></div>
                </div>
                <div id="rootPasswordCard" class="card" style="display:none; border-color: var(--warning);">
                    <div class="card-title" style="color: var(--warning);">Root Password Required</div>
                    <p style="font-size:13px;color:var(--text-muted);margin-bottom:12px;">
                        This device has no root password configured. Junos requires a root password before any configuration
                        changes can be committed. Set one now before proceeding.
                    </p>
                    <div id="rootPwAlert" class="alert"></div>
                    <div class="form-row">
                        <div class="form-group"><label>Root Password</label><input type="password" id="rootPw1" placeholder="Min 6 characters"></div>
                        <div class="form-group"><label>Confirm Root Password</label><input type="password" id="rootPw2" placeholder="Re-enter password"></div>
                    </div>
                    <div class="btn-group"><button id="btnSetRootPw" class="btn btn-danger" onclick="setRootPassword()">Set Root Password</button></div>
                </div>
            </div>

            <!-- DEVICE INFO -->
            <div id="page-info" class="page">
                <div class="page-title">Device Information</div>
                <div class="page-subtitle">Query the device for identification details.</div>
                <div class="card">
                    <div id="infoAlert" class="alert"></div>
                    <div class="info-grid" id="deviceInfoGrid">
                        <div class="info-item"><label>Hostname</label><div class="value empty" id="infoHostname">--</div></div>
                        <div class="info-item"><label>Model</label><div class="value empty" id="infoModel">--</div></div>
                        <div class="info-item"><label>Firmware</label><div class="value empty" id="infoFirmware">--</div></div>
                        <div class="info-item"><label>Serial Number</label><div class="value empty" id="infoSerial">--</div></div>
                    </div>
                    <div class="btn-group"><button id="btnGetInfo" class="btn btn-primary" onclick="getDeviceInfo()">Get Device Info</button></div>
                </div>
            </div>

            <!-- USER ACCOUNT -->
            <div id="page-account" class="page">
                <div class="page-title">User Account</div>
                <div class="page-subtitle">Create new accounts or update passwords for existing users.</div>

                <div class="card">
                    <div class="card-title">Existing Users</div>
                    <div id="userListAlert" class="alert"></div>
                    <div id="userListContainer" style="margin-bottom:12px;">
                        <p style="font-size:13px;color:var(--text-muted);">Click "Refresh Users" to load the user list from the device.</p>
                    </div>
                    <div class="btn-group" style="margin-top:0;"><button id="btnRefreshUsers" class="btn btn-outline" onclick="refreshUsers()">Refresh Users</button></div>
                </div>

                <div class="card">
                    <div class="card-title">Create New User</div>
                    <div id="createAccountAlert" class="alert"></div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Username</label>
                            <input type="text" id="newUsername" placeholder="e.g. vc3admin" value="vc3admin">
                        </div>
                        <div class="form-group">
                            <label>Class</label>
                            <select id="newUserClass">
                                <option value="super-user" selected>super-user</option>
                                <option value="operator">operator</option>
                                <option value="read-only">read-only</option>
                            </select>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group"><label>Password</label><input type="password" id="newUserPass1" placeholder="Min 6 characters"></div>
                        <div class="form-group"><label>Confirm Password</label><input type="password" id="newUserPass2" placeholder="Re-enter password"></div>
                    </div>
                    <div class="btn-group"><button id="btnCreateAccount" class="btn btn-success" onclick="createAccount()">Create User</button></div>
                </div>

                <div class="card">
                    <div class="card-title">Update Password</div>
                    <div id="updatePwAlert" class="alert"></div>
                    <p style="font-size:13px;color:var(--text-muted);margin-bottom:12px;">Select an existing user and set a new password.</p>
                    <div class="form-group">
                        <label>User</label>
                        <select id="updatePwUser"><option value="">-- Refresh users first --</option></select>
                    </div>
                    <div class="form-row">
                        <div class="form-group"><label>New Password</label><input type="password" id="updatePwPass1" placeholder="Min 6 characters"></div>
                        <div class="form-group"><label>Confirm Password</label><input type="password" id="updatePwPass2" placeholder="Re-enter password"></div>
                    </div>
                    <div class="btn-group"><button id="btnUpdatePw" class="btn btn-primary" onclick="updatePassword()">Update Password</button></div>
                </div>
            </div>

            <!-- MANAGEMENT IP -->
            <div id="page-network" class="page">
                <div class="page-title">Management Interface</div>
                <div class="page-subtitle">Configure a management IP so you can SCP firmware from your laptop.</div>
                <div class="card">
                    <div id="networkAlert" class="alert"></div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Interface</label>
                            <select id="mgmtInterface">
                                <option value="">Auto-detect</option>
                                <option value="vme">vme (EX switches)</option>
                                <option value="fxp0">fxp0 (SRX firewalls)</option>
                                <option value="me0">me0 (other)</option>
                            </select>
                            <div class="hint">Leave on auto-detect unless you know the interface name.</div>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group"><label>IP Address (CIDR)</label><input type="text" id="mgmtIp" placeholder="192.168.1.2/24"></div>
                        <div class="form-group"><label>Gateway (optional)</label><input type="text" id="mgmtGw" placeholder="192.168.1.1"></div>
                    </div>
                    <div class="btn-group"><button id="btnSetMgmt" class="btn btn-primary" onclick="setMgmtIp()">Configure Management IP</button></div>
                </div>
                <div class="card">
                    <div class="card-title">Enable Remote Management</div>
                    <p style="font-size:13px;color:var(--text-muted);margin-bottom:12px;">
                        Enable NETCONF and SSH so this device can be managed remotely by the Juniper Device Manager.
                    </p>
                    <div id="netconfAlert" class="alert"></div>
                    <div class="form-group">
                        <label class="checkbox-group"><input type="checkbox" id="enableSsh" checked> SSH (required for remote access)</label>
                    </div>
                    <div class="form-group">
                        <label class="checkbox-group"><input type="checkbox" id="enableNetconf" checked> NETCONF over SSH (port 830 - used by Device Manager)</label>
                    </div>
                    <div class="form-group">
                        <label class="checkbox-group"><input type="checkbox" id="enableRest"> REST API (optional - HTTP access)</label>
                    </div>
                    <div class="btn-group"><button id="btnEnableNetconf" class="btn btn-success" onclick="enableNetconf()">Enable Remote Access</button></div>
                </div>
            </div>

            <!-- FIRMWARE -->
            <div id="page-firmware" class="page">
                <div class="page-title">Firmware Upgrade</div>
                <div class="page-subtitle">Transfer and install Junos firmware on this device.</div>
                <div class="card">
                    <div class="card-title">Step 1: Transfer Firmware via SCP</div>
                    <div id="fwScpAlert" class="alert"></div>
                    <p style="font-size:13px;color:var(--text-muted);margin-bottom:12px;">The device will SCP the firmware image from your laptop. You need an SSH server running on your laptop.</p>
                    <div class="form-row">
                        <div class="form-group"><label>Your Laptop IP</label><input type="text" id="fwLaptopIp" placeholder="192.168.1.100"></div>
                        <div class="form-group"><label>SSH Username</label><input type="text" id="fwScpUser" placeholder="admin"></div>
                    </div>
                    <div class="form-group">
                        <label>Firmware File Path (on your laptop)</label>
                        <input type="text" id="fwScpPath" placeholder="/c/temp/junos-arm-32-21.4R3-S7.2.tgz">
                        <div class="hint">Use forward slashes. For Windows paths: /c/Users/you/Downloads/firmware.tgz</div>
                    </div>
                    <div class="btn-group">
                        <button id="btnScpFw" class="btn btn-primary" onclick="scpFirmware()">Start SCP Transfer</button>
                        <button class="btn btn-outline" onclick="listFirmwareFiles()">List /var/tmp/ Files</button>
                    </div>
                    <div id="fwFileList" style="display:none;margin-top:12px;">
                        <div class="card-title">Files on Device (/var/tmp/):</div>
                        <pre class="config-viewer" id="fwFileListContent" style="max-height:150px;"></pre>
                    </div>
                </div>
                <div class="card">
                    <div class="card-title">Step 2: Install Firmware</div>
                    <div id="fwInstallAlert" class="alert"></div>
                    <div class="form-group">
                        <label>Image Path on Device</label>
                        <input type="text" id="fwImagePath" placeholder="/var/tmp/junos-arm-32-21.4R3-S7.2.tgz">
                    </div>
                    <div class="form-group">
                        <label class="checkbox-group"><input type="checkbox" id="fwReboot" checked> Reboot automatically after install</label>
                    </div>
                    <div class="btn-group"><button id="btnInstallFw" class="btn btn-danger" onclick="installFirmware()">Install Firmware</button></div>
                    <div id="fwProgress" style="display:none;margin-top:12px;">
                        <div style="font-size:13px;color:var(--warning);">Firmware installation in progress. This can take 10-30 minutes...</div>
                        <div class="progress-bar"><div class="progress-fill indeterminate"></div></div>
                    </div>
                </div>
            </div>

            <!-- CONFIG -->
            <div id="page-config" class="page">
                <div class="page-title">Configuration</div>
                <div class="page-subtitle">Export the running config or load a config file onto the device.</div>
                <div class="card">
                    <div class="card-title">Export Running Config</div>
                    <div id="configAlert" class="alert"></div>
                    <div class="btn-group" style="margin-top:0;margin-bottom:16px;">
                        <button id="btnGetConfig" class="btn btn-primary" onclick="getConfig()">Retrieve Config</button>
                        <button id="btnDownloadConfig" class="btn btn-outline" onclick="downloadConfig()" style="display:none;">Download .txt</button>
                    </div>
                    <div id="configContent" class="config-viewer" style="display:none;"></div>
                </div>
                <div class="card">
                    <div class="card-title">Load Configuration</div>
                    <p style="font-size:13px;color:var(--text-muted);margin-bottom:12px;">
                        Upload a .txt or .conf file, or paste config commands directly. Supports both <strong>set</strong> format
                        and <strong>hierarchical</strong> (curly brace) format. Uses <em>commit confirmed</em> for safety.
                    </p>
                    <div id="loadConfigAlert" class="alert"></div>
                    <div class="form-group">
                        <label>Config File (.txt / .conf)</label>
                        <input type="file" id="configFileInput" accept=".txt,.conf,.cfg" style="padding:6px;"
                               onchange="loadConfigFile(this)">
                        <div class="hint">Or paste config directly in the box below.</div>
                    </div>
                    <div class="form-group">
                        <label>Configuration</label>
                        <textarea id="loadConfigText" rows="10" placeholder="Paste config here, or use the file picker above.&#10;&#10;Supports set format:&#10;  set system host-name MY-SWITCH&#10;  set system name-server 8.8.8.8&#10;&#10;Or hierarchical format:&#10;  system {&#10;      host-name MY-SWITCH;&#10;  }"></textarea>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>Load Mode</label>
                            <select id="loadConfigMode">
                                <option value="merge">Merge (add to existing config)</option>
                                <option value="replace">Replace (replace matching sections)</option>
                                <option value="override">Override (full config replace - use with caution)</option>
                            </select>
                            <div class="hint">Merge is safest for partial configs. Override replaces the entire config.</div>
                        </div>
                        <div class="form-group">
                            <label>Commit Confirmed (minutes)</label>
                            <input type="number" id="loadConfigConfirm" value="5" min="0" max="60">
                            <div class="hint">Auto-rollback timer. Set to 0 to skip (not recommended).</div>
                        </div>
                    </div>
                    <div id="loadConfigDiff" class="config-viewer" style="display:none;margin-bottom:12px;max-height:200px;"></div>
                    <div class="btn-group">
                        <button id="btnLoadConfig" class="btn btn-danger" onclick="doLoadConfig()">Load Config to Device</button>
                    </div>
                </div>
            </div>

            <!-- TERMINAL -->
            <div id="page-terminal" class="page">
                <div class="page-title">Raw Terminal</div>
                <div class="page-subtitle">Send Junos CLI commands directly to the device.</div>
                <div class="terminal-wrap">
                    <div class="terminal-output" id="terminalOutput"></div>
                    <div class="terminal-input-row">
                        <span class="terminal-prompt">junos&gt;</span>
                        <input class="terminal-input" id="terminalInput" type="text" placeholder="Type a command..."
                               onkeydown="if(event.key==='Enter') sendTerminalCmd()">
                    </div>
                </div>
                <div style="margin-top:8px;font-size:11px;color:var(--text-muted);">
                    Tip: Use &quot;configure&quot; to enter config mode, &quot;exit&quot; to leave it. For interactive prompts during SCP, use the serial input box below.
                </div>
                <div class="card" style="margin-top:16px;">
                    <div class="card-title">Serial Input (for interactive prompts)</div>
                    <p style="font-size:12px;color:var(--text-muted);margin-bottom:8px;">Send raw text for host-key confirmations, password prompts during SCP, etc.</p>
                    <div style="display:flex;gap:8px;">
                        <input type="text" id="serialInput" placeholder="yes / password / etc." style="flex:1;"
                               onkeydown="if(event.key==='Enter') sendSerialInput()">
                        <button class="btn btn-outline" onclick="sendSerialInput()">Send</button>
                    </div>
                </div>
            </div>
        </div>

        <div class="log-resize" id="logResize"></div>
        <div class="log-panel" id="logPanel">
            <div class="log-header">
                <span class="log-header-title">Console Log</span>
                <button class="btn-shutdown" onclick="clearLog()" style="font-size:11px;">Clear</button>
            </div>
            <div class="log-body" id="logBody"></div>
        </div>
    </div>
</div>

<script>
var state = { connected: false, loggedIn: false, needsRootPassword: false, device: {}, lastLogCount: 0 };
var currentPage = 'connect';
var configText = '';
var portData = {};

function initTheme() {
    var saved = localStorage.getItem('jcs-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
}
function toggleTheme() {
    var c = document.documentElement.getAttribute('data-theme') || 'dark';
    var n = c === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', n);
    localStorage.setItem('jcs-theme', n);
}
initTheme();

function api(method, path, body) {
    var opts = { method: method, headers: { 'Content-Type': 'application/json' } };
    if (body) opts.body = JSON.stringify(body);
    return fetch(path, opts).then(function(r) { return r.json(); });
}

function showPage(page) {
    var nav = document.querySelector('.nav-item[data-page="'+page+'"]');
    if (nav && nav.classList.contains('disabled')) return;
    document.querySelectorAll('.page').forEach(function(p){p.classList.remove('active');});
    document.querySelectorAll('.nav-item').forEach(function(n){n.classList.remove('active');});
    document.getElementById('page-'+page).classList.add('active');
    if (nav) nav.classList.add('active');
    currentPage = page;
}

function updateNav() {
    ['login','info','account','network','firmware','config','terminal'].forEach(function(p){
        var nav = document.querySelector('.nav-item[data-page="'+p+'"]');
        if (!nav) return;
        nav.classList.toggle('disabled', p === 'login' ? !state.connected : !state.loggedIn);
    });
    var badge = document.getElementById('statusBadge');
    var text = document.getElementById('statusText');
    badge.className = 'status-badge';
    if (state.loggedIn) { badge.classList.add('logged-in'); text.textContent = state.device.hostname || 'Logged In'; }
    else if (state.connected) { badge.classList.add('connected'); text.textContent = 'Connected'; }
    else { badge.classList.add('disconnected'); text.textContent = 'Disconnected'; }
}

function showAlert(id, type, msg) {
    var el = document.getElementById(id);
    el.className = 'alert alert-'+type+' show';
    el.innerHTML = msg;
}
function hideAlert(id) { var el = document.getElementById(id); if(el){el.className='alert';el.innerHTML='';} }

function setLoading(btnId, loading) {
    var btn = document.getElementById(btnId);
    if (!btn) return;
    btn.disabled = loading;
    if (loading) { btn.dataset.origText = btn.innerHTML; btn.innerHTML = '<span class="spinner"></span> Working...'; }
    else { btn.innerHTML = btn.dataset.origText || btn.innerHTML; }
}

function refreshPorts() {
    api('GET','/api/ports').then(function(data){
        var sel = document.getElementById('comPortSelect');
        sel.innerHTML = '';
        portData = {};
        if (data.ports && data.ports.length > 0) {
            data.ports.forEach(function(p){
                var opt = document.createElement('option');
                opt.value = p.port;
                opt.textContent = p.port + ' - ' + p.description;
                sel.appendChild(opt);
                portData[p.port] = p;
            });
            var first = data.ports[0];
            document.getElementById('portDescription').textContent = first.hwid || '';
        } else {
            sel.innerHTML = '<option value="">No COM ports found</option>';
            document.getElementById('portDescription').textContent = '';
        }
    });
}

document.addEventListener('change', function(e){
    if (e.target.id === 'comPortSelect') {
        var p = portData[e.target.value];
        document.getElementById('portDescription').textContent = p ? (p.hwid||'') : '';
    }
});

function connectPort() {
    var port = document.getElementById('comPortSelect').value;
    var baud = document.getElementById('baudSelect').value;
    if (!port) { showAlert('connectAlert','danger','Select a COM port.'); return; }
    hideAlert('connectAlert');
    setLoading('btnConnect', true);
    api('POST','/api/connect',{port:port, baudRate:parseInt(baud)}).then(function(data){
        setLoading('btnConnect', false);
        if (data.success) {
            state.connected = true;
            showAlert('connectAlert','success','Connected to '+port+' at '+baud+' baud.');
            document.getElementById('btnConnect').style.display='none';
            document.getElementById('btnDisconnect').style.display='';
            document.getElementById('sidebarPort').textContent=port;
            document.getElementById('sidebarBaud').textContent=baud;
            updateNav();
            setTimeout(function(){showPage('login');},500);
        } else { showAlert('connectAlert','danger',data.message); }
    });
}

function disconnectPort() {
    api('POST','/api/disconnect').then(function(){
        state.connected=false; state.loggedIn=false; state.device={};
        document.getElementById('btnConnect').style.display='';
        document.getElementById('btnDisconnect').style.display='none';
        document.getElementById('sidebarPort').textContent='--';
        showAlert('connectAlert','info','Disconnected.');
        updateNav(); showPage('connect'); clearDeviceInfo();
    });
}

function doLogin() {
    hideAlert('loginAlert');
    setLoading('btnLogin', true);
    api('POST','/api/login',{
        tryFactoryDefault: document.getElementById('tryFactory').checked,
        username: document.getElementById('loginUser').value,
        password: document.getElementById('loginPass').value
    }).then(function(data){
        setLoading('btnLogin', false);
        if (data.success) {
            state.loggedIn = true;
            var loginMsg = data.message;
            if (data.needsRootPassword) {
                state.needsRootPassword = true;
                document.getElementById('rootPasswordCard').style.display = '';
                loginMsg += ' <strong style="color:var(--warning);">Root password is not set.</strong> You must set it below before making any configuration changes.';
                showAlert('loginAlert','warning',loginMsg);
            } else {
                showAlert('loginAlert','success',loginMsg);
                var nav = document.querySelector('.nav-item[data-page="login"]');
                if (nav) nav.classList.add('done');
                setTimeout(function(){showPage('info');},600);
            }
            updateNav();
        } else {
            if (data.needsCredentials) showAlert('loginAlert','warning',data.message+' Enter credentials below.');
            else showAlert('loginAlert','danger',data.message);
        }
    });
}

function setRootPassword() {
    hideAlert('rootPwAlert');
    var p1 = document.getElementById('rootPw1').value;
    var p2 = document.getElementById('rootPw2').value;
    if (!p1 || p1.length < 6) { showAlert('rootPwAlert','danger','Root password must be at least 6 characters.'); return; }
    if (p1 !== p2) { showAlert('rootPwAlert','danger','Passwords do not match.'); return; }
    setLoading('btnSetRootPw', true);
    api('POST','/api/set-root-password',{rootPassword: p1}).then(function(data){
        setLoading('btnSetRootPw', false);
        if (data.success) {
            state.needsRootPassword = false;
            showAlert('rootPwAlert','success',data.message);
            showAlert('loginAlert','success','Logged in. Root password is configured.');
            document.getElementById('rootPasswordCard').style.display = 'none';
            var nav = document.querySelector('.nav-item[data-page="login"]');
            if (nav) nav.classList.add('done');
            setTimeout(function(){showPage('info');},600);
        } else {
            showAlert('rootPwAlert','danger',data.message);
        }
    });
}

function getDeviceInfo() {
    hideAlert('infoAlert');
    setLoading('btnGetInfo', true);
    api('GET','/api/device-info').then(function(data){
        setLoading('btnGetInfo', false);
        if (data.success) {
            state.device = {hostname:data.hostname,model:data.model,firmware:data.firmware,serial:data.serial};
            setInfoField('infoHostname',data.hostname);
            setInfoField('infoModel',data.model);
            setInfoField('infoFirmware',data.firmware);
            setInfoField('infoSerial',data.serial);
            updateNav();
            var nav = document.querySelector('.nav-item[data-page="info"]');
            if (nav) nav.classList.add('done');
        } else { showAlert('infoAlert','danger',data.message); }
    });
}
function setInfoField(id,val){var el=document.getElementById(id);el.textContent=val||'--';el.classList.toggle('empty',!val);}
function clearDeviceInfo(){['infoHostname','infoModel','infoFirmware','infoSerial'].forEach(function(id){setInfoField(id,'');});}

function refreshUsers() {
    hideAlert('userListAlert');
    setLoading('btnRefreshUsers', true);
    api('GET','/api/users').then(function(data){
        setLoading('btnRefreshUsers', false);
        if (data.success) {
            var container = document.getElementById('userListContainer');
            var pwSelect = document.getElementById('updatePwUser');
            pwSelect.innerHTML = '<option value="">-- Select user --</option>';
            if (data.users && data.users.length > 0) {
                var html = '<table style="width:100%;border-collapse:collapse;font-size:13px;">';
                html += '<tr style="border-bottom:1px solid var(--border);"><th style="text-align:left;padding:8px;color:var(--text-muted);">Username</th><th style="text-align:left;padding:8px;color:var(--text-muted);">Class</th></tr>';
                data.users.forEach(function(u){
                    html += '<tr style="border-bottom:1px solid var(--border);"><td style="padding:8px;font-family:var(--font-mono);font-weight:600;">'+u.username+'</td><td style="padding:8px;color:var(--text-muted);">'+u['class']+'</td></tr>';
                    var opt = document.createElement('option');
                    opt.value = u.username; opt.textContent = u.username + ' (' + u['class'] + ')';
                    pwSelect.appendChild(opt);
                });
                html += '</table>';
                container.innerHTML = html;
            } else {
                var rawHtml = '<p style="font-size:13px;color:var(--text-muted);">No users parsed from device output.</p>';
                if (data.raw) rawHtml += '<pre class="config-viewer" style="max-height:150px;margin-top:8px;font-size:11px;">'+data.raw.replace(/</g,'&lt;')+'</pre>';
                container.innerHTML = rawHtml;
            }
        } else { showAlert('userListAlert','danger',data.message); }
    });
}

function createAccount() {
    hideAlert('createAccountAlert');
    if (state.needsRootPassword) {
        showAlert('createAccountAlert','danger','Root password must be set first. Go back to the Login page and set it.');
        return;
    }
    var username = document.getElementById('newUsername').value.trim();
    var userClass = document.getElementById('newUserClass').value;
    var p1 = document.getElementById('newUserPass1').value;
    var p2 = document.getElementById('newUserPass2').value;
    if (!username) { showAlert('createAccountAlert','danger','Enter a username.'); return; }
    if (!p1 || p1.length < 6) { showAlert('createAccountAlert','danger','Password must be at least 6 characters.'); return; }
    if (p1 !== p2) { showAlert('createAccountAlert','danger','Passwords do not match.'); return; }
    setLoading('btnCreateAccount', true);
    api('POST','/api/create-account',{username:username, password:p1, userClass:userClass}).then(function(data){
        setLoading('btnCreateAccount', false);
        if (data.success) {
            showAlert('createAccountAlert','success',data.message);
            var nav = document.querySelector('.nav-item[data-page="account"]'); if(nav) nav.classList.add('done');
            refreshUsers();
        } else {
            showAlert('createAccountAlert','danger',data.message||'Operation failed.');
        }
    });
}

function updatePassword() {
    hideAlert('updatePwAlert');
    var username = document.getElementById('updatePwUser').value;
    var p1 = document.getElementById('updatePwPass1').value;
    var p2 = document.getElementById('updatePwPass2').value;
    if (!username) { showAlert('updatePwAlert','danger','Select a user.'); return; }
    if (!p1 || p1.length < 6) { showAlert('updatePwAlert','danger','Password must be at least 6 characters.'); return; }
    if (p1 !== p2) { showAlert('updatePwAlert','danger','Passwords do not match.'); return; }
    setLoading('btnUpdatePw', true);
    api('POST','/api/update-password',{username:username, password:p1}).then(function(data){
        setLoading('btnUpdatePw', false);
        if (data.success) {
            showAlert('updatePwAlert','success',data.message);
        } else {
            showAlert('updatePwAlert','danger',data.message||'Operation failed.');
        }
    });
}

function setMgmtIp() {
    hideAlert('networkAlert');
    var ip=document.getElementById('mgmtIp').value;
    if(!ip){showAlert('networkAlert','danger','Enter an IP address.');return;}
    setLoading('btnSetMgmt', true);
    api('POST','/api/mgmt-ip',{
        ipAddress:ip, gateway:document.getElementById('mgmtGw').value,
        interface:document.getElementById('mgmtInterface').value||null
    }).then(function(data){
        setLoading('btnSetMgmt', false);
        if(data.success){showAlert('networkAlert','success',data.message);var nav=document.querySelector('.nav-item[data-page="network"]');if(nav)nav.classList.add('done');}
        else showAlert('networkAlert','danger',data.message);
    });
}

function enableNetconf() {
    hideAlert('netconfAlert');
    setLoading('btnEnableNetconf', true);
    api('POST','/api/enable-netconf',{
        ssh: document.getElementById('enableSsh').checked,
        netconf: document.getElementById('enableNetconf').checked,
        rest: document.getElementById('enableRest').checked
    }).then(function(data){
        setLoading('btnEnableNetconf', false);
        if(data.success) showAlert('netconfAlert','success',data.message);
        else showAlert('netconfAlert','danger',data.message);
    });
}

function scpFirmware() {
    hideAlert('fwScpAlert');
    var ip=document.getElementById('fwLaptopIp').value, user=document.getElementById('fwScpUser').value, path=document.getElementById('fwScpPath').value;
    if(!ip||!user||!path){showAlert('fwScpAlert','danger','Fill in all SCP fields.');return;}
    setLoading('btnScpFw', true);
    api('POST','/api/firmware/scp',{laptopIp:ip,scpUser:user,scpPath:path}).then(function(data){
        setLoading('btnScpFw', false);
        if(data.success){
            showAlert('fwScpAlert','warning',data.message+'<br>Check the <b>Terminal</b> page to handle host-key and password prompts.');
            document.getElementById('fwImagePath').value=data.remoteFile||'';
        } else showAlert('fwScpAlert','danger',data.message);
    });
}
function listFirmwareFiles(){
    api('POST','/api/firmware/list').then(function(data){
        document.getElementById('fwFileList').style.display='';
        document.getElementById('fwFileListContent').textContent=data.output||'(empty)';
    });
}
function installFirmware() {
    hideAlert('fwInstallAlert');
    var path=document.getElementById('fwImagePath').value, reboot=document.getElementById('fwReboot').checked;
    if(!path){showAlert('fwInstallAlert','danger','Enter the image path.');return;}
    if(!confirm('Install firmware and '+(reboot?'REBOOT':'stage (no reboot)')+'?\n\nImage: '+path)) return;
    setLoading('btnInstallFw', true);
    document.getElementById('fwProgress').style.display='';
    api('POST','/api/firmware/install',{imagePath:path,reboot:reboot}).then(function(data){
        setLoading('btnInstallFw', false);
        if(data.success){showAlert('fwInstallAlert','warning',data.message);var nav=document.querySelector('.nav-item[data-page="firmware"]');if(nav)nav.classList.add('done');}
        else{showAlert('fwInstallAlert','danger',data.message);document.getElementById('fwProgress').style.display='none';}
    });
}

function getConfig() {
    hideAlert('configAlert');
    setLoading('btnGetConfig', true);
    api('GET','/api/config').then(function(data){
        setLoading('btnGetConfig', false);
        if(data.success){
            configText=data.config||'';
            document.getElementById('configContent').textContent=configText;
            document.getElementById('configContent').style.display='';
            document.getElementById('btnDownloadConfig').style.display='';
            showAlert('configAlert','success','Configuration retrieved ('+configText.length+' characters).');
        } else showAlert('configAlert','danger',data.message);
    });
}
function downloadConfig(){
    var name=(state.device.hostname||'device')+'_config_'+new Date().toISOString().replace(/[:.]/g,'-').slice(0,19)+'.txt';
    var blob=new Blob([configText],{type:'text/plain'});
    var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=name; a.click();
}

function loadConfigFile(input) {
    if (!input.files || !input.files[0]) return;
    var file = input.files[0];
    var reader = new FileReader();
    reader.onload = function(e) {
        document.getElementById('loadConfigText').value = e.target.result;
        showAlert('loadConfigAlert','info','Loaded ' + file.name + ' (' + e.target.result.length + ' characters).');
    };
    reader.readAsText(file);
}

function doLoadConfig() {
    hideAlert('loadConfigAlert');
    var config = document.getElementById('loadConfigText').value;
    var mode = document.getElementById('loadConfigMode').value;
    var confirm = parseInt(document.getElementById('loadConfigConfirm').value) || 5;
    if (!config || !config.trim()) { showAlert('loadConfigAlert','danger','Paste or load a config first.'); return; }
    var lines = config.trim().split('\n').filter(function(l){return l.trim();}).length;
    var modeLabel = {merge:'MERGE',replace:'REPLACE',override:'FULL OVERRIDE'}[mode];
    if (!window.confirm('Load ' + lines + ' lines of config using ' + modeLabel + ' mode?\n\nCommit confirmed: ' + confirm + ' min auto-rollback.')) return;
    setLoading('btnLoadConfig', true);
    document.getElementById('loadConfigDiff').style.display = 'none';
    api('POST','/api/load-config',{config:config, mode:mode, confirmMinutes:confirm}).then(function(data){
        setLoading('btnLoadConfig', false);
        if (data.success) {
            showAlert('loadConfigAlert','success',data.message);
            if (data.diff) {
                document.getElementById('loadConfigDiff').textContent = data.diff;
                document.getElementById('loadConfigDiff').style.display = '';
            }
        } else {
            var msg = data.message;
            if (data.errors && data.errors.length) {
                msg += '<br><br><strong>Errors:</strong><br>' + data.errors.map(function(e){return '&bull; ' + e;}).join('<br>');
            }
            showAlert('loadConfigAlert','danger',msg);
        }
    });
}

function sendTerminalCmd(){
    var input=document.getElementById('terminalInput'), cmd=input.value;
    if(!cmd) return; input.value='';
    appendTerminal('> '+cmd,'color:#38bdf8;');
    api('POST','/api/command',{command:cmd}).then(function(data){ appendTerminal(data.output||data.message||'(no output)'); });
}
function sendSerialInput(){
    var input=document.getElementById('serialInput'), text=input.value; input.value='';
    api('POST','/api/serial-input',{input:text}).then(function(data){ if(data.output) appendTerminal(data.output); });
}
function appendTerminal(text,style){
    var el=document.getElementById('terminalOutput'), line=document.createElement('div');
    line.textContent=text; if(style)line.setAttribute('style',style);
    el.appendChild(line); el.scrollTop=el.scrollHeight;
}

function pollLog(){
    api('GET','/api/log').then(function(data){
        if(!data.entries) return;
        var body=document.getElementById('logBody');
        if(data.entries.length > state.lastLogCount){
            data.entries.slice(state.lastLogCount).forEach(function(e){
                var div=document.createElement('div');
                div.className='log-entry '+e.level;
                div.textContent='['+e.level+'] '+e.time+'  '+e.message;
                body.appendChild(div);
            });
            state.lastLogCount=data.entries.length;
            body.scrollTop=body.scrollHeight;
        }
    }).catch(function(){});
}
function clearLog(){ document.getElementById('logBody').innerHTML=''; }

(function(){
    var resizer=document.getElementById('logResize'), panel=document.getElementById('logPanel'), startY, startH;
    resizer.addEventListener('mousedown',function(e){
        startY=e.clientY; startH=panel.offsetHeight;
        document.addEventListener('mousemove',onMove); document.addEventListener('mouseup',onUp); e.preventDefault();
    });
    function onMove(e){panel.style.height=Math.max(60,startH-(e.clientY-startY))+'px';}
    function onUp(){document.removeEventListener('mousemove',onMove);document.removeEventListener('mouseup',onUp);}
})();

function shutdown(){
    if(!confirm('Shut down the console setup server?')) return;
    api('POST','/api/shutdown').then(function(){
        document.body.innerHTML='<div style="display:flex;align-items:center;justify-content:center;height:100vh;"><div style="text-align:center;color:var(--text-muted);"><h2>Server Stopped</h2><p>You can close this tab.</p></div></div>';
    });
}

refreshPorts();
setInterval(pollLog, 1500);
pollLog();
updateNav();
</script>
</body>
</html>"""


# ============================================================================
# HTTP REQUEST HANDLER
# ============================================================================
class RequestHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        # Suppress default HTTP logging
        pass

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

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def do_GET(self):
        path = urlparse(self.path).path

        if path in ("/", "/index.html"):
            self._send_html(HTML_CONTENT)
            return

        if path == "/api/ports":
            ports = get_available_ports()
            self._send_json({"ports": ports})
            return

        if path == "/api/status":
            self._send_json({
                "connected": is_connected,
                "loggedIn": is_logged_in,
                "configMode": is_config_mode,
                "device": device_info,
                "comPort": ser.port if ser and ser.is_open else "",
                "baudRate": ser.baudrate if ser and ser.is_open else 9600,
            })
            return

        if path == "/api/device-info":
            if not is_logged_in:
                self._send_json({"success": False, "message": "Not logged in."})
                return
            self._send_json(get_device_info())
            return

        if path == "/api/users":
            if not is_logged_in:
                self._send_json({"success": False, "message": "Not logged in."})
                return
            self._send_json(get_user_list())
            return

        if path == "/api/config":
            if not is_logged_in:
                self._send_json({"success": False, "message": "Not logged in."})
                return
            config = get_running_config()
            self._send_json({"success": True, "config": config})
            return

        if path == "/api/log":
            self._send_json({"entries": session_log})
            return

        self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()

        if path == "/api/connect":
            port_name = body.get("port", "")
            baud = int(body.get("baudRate", 9600))
            if not port_name:
                self._send_json({"success": False, "message": "No port specified."})
                return
            self._send_json(connect_serial(port_name, baud))
            return

        if path == "/api/disconnect":
            disconnect_serial()
            self._send_json({"success": True, "message": "Disconnected."})
            return

        if path == "/api/login":
            if not is_connected:
                self._send_json({"success": False, "message": "Not connected to a serial port."})
                return
            result = do_login(
                username=body.get("username", ""),
                password=body.get("password", ""),
                try_factory=bool(body.get("tryFactoryDefault", False))
            )
            self._send_json(result)
            return

        if path == "/api/set-root-password":
            if not is_logged_in:
                self._send_json({"success": False, "message": "Not logged in."})
                return
            self._send_json(set_root_password(body.get("rootPassword", "")))
            return

        if path == "/api/create-account":
            if not is_logged_in:
                self._send_json({"success": False, "message": "Not logged in."})
                return
            username = body.get("username", "").strip()
            pw = body.get("password", "")
            user_class = body.get("userClass", "super-user")
            if not username:
                self._send_json({"success": False, "message": "Username is required."})
                return
            if not pw or len(pw) < 6:
                self._send_json({"success": False, "message": "Password must be at least 6 characters."})
                return
            self._send_json(create_user_account(username, pw, user_class))
            return

        if path == "/api/update-password":
            if not is_logged_in:
                self._send_json({"success": False, "message": "Not logged in."})
                return
            username = body.get("username", "").strip()
            pw = body.get("password", "")
            if not username:
                self._send_json({"success": False, "message": "Select a user."})
                return
            if not pw or len(pw) < 6:
                self._send_json({"success": False, "message": "Password must be at least 6 characters."})
                return
            self._send_json(update_user_password(username, pw))
            return

        if path == "/api/mgmt-ip":
            if not is_logged_in:
                self._send_json({"success": False, "message": "Not logged in."})
                return
            ip = body.get("ipAddress", "")
            if not re.match(r'^\d+\.\d+\.\d+\.\d+/\d+$', ip):
                self._send_json({"success": False, "message": "Use CIDR notation (e.g. 192.168.1.2/24)."})
                return
            self._send_json(set_management_ip(ip, body.get("gateway"), body.get("interface")))
            return

        if path == "/api/enable-netconf":
            if not is_logged_in:
                self._send_json({"success": False, "message": "Not logged in."})
                return
            self._send_json(enable_netconf(
                enable_ssh=bool(body.get("ssh", True)),
                enable_netconf_ssh=bool(body.get("netconf", True)),
                enable_rest=bool(body.get("rest", False)),
            ))
            return

        if path == "/api/firmware/scp":
            if not is_logged_in:
                self._send_json({"success": False, "message": "Not logged in."})
                return
            self._send_json(scp_firmware(body.get("laptopIp", ""), body.get("scpUser", ""), body.get("scpPath", "")))
            return

        if path == "/api/firmware/list":
            if not is_logged_in:
                self._send_json({"success": False, "message": "Not logged in."})
                return
            output = send_command("file list /var/tmp/", timeout_seconds=10)
            self._send_json({"success": True, "output": output})
            return

        if path == "/api/firmware/install":
            if not is_logged_in:
                self._send_json({"success": False, "message": "Not logged in."})
                return
            self._send_json(install_firmware(body.get("imagePath", ""), bool(body.get("reboot", False))))
            return

        if path == "/api/load-config":
            if not is_logged_in:
                self._send_json({"success": False, "message": "Not logged in."})
                return
            config_text = body.get("config", "")
            mode = body.get("mode", "merge")
            confirm = int(body.get("confirmMinutes", 5))
            if mode not in ("merge", "override", "replace"):
                self._send_json({"success": False, "message": "Mode must be 'merge', 'override', or 'replace'."})
                return
            self._send_json(load_config(config_text, mode=mode, confirm_minutes=confirm))
            return

        if path == "/api/command":
            if not is_logged_in:
                self._send_json({"success": False, "message": "Not logged in."})
                return
            cmd = body.get("command", "")
            if not cmd:
                self._send_json({"success": False, "message": "No command provided."})
                return
            output = raw_command(cmd)
            self._send_json({"success": True, "output": output})
            return

        if path == "/api/serial-input":
            if not is_connected:
                self._send_json({"success": False, "message": "Not connected."})
                return
            send_data(body.get("input", ""))
            time.sleep(0.5)
            output = read_response(timeout_seconds=3)
            self._send_json({"success": True, "output": output})
            return

        if path == "/api/shutdown":
            self._send_json({"success": True, "message": "Shutting down."})
            threading.Thread(target=lambda: (time.sleep(0.5), os._exit(0)), daemon=True).start()
            return

        self._send_json({"error": "Not found"}, 404)


# ============================================================================
# MAIN
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description="Juniper Console Setup - Browser GUI")
    parser.add_argument("--port", type=int, default=8280, help="Web server port (default: 8280)")
    parser.add_argument("--com", type=str, default="", help="Auto-connect to this COM port")
    parser.add_argument("--baud", type=int, default=9600, help="Serial baud rate (default: 9600)")
    parser.add_argument("--no-browser", action="store_true", help="Don't auto-open browser")
    args = parser.parse_args()

    url = f"http://localhost:{args.port}/"

    print()
    print("  " + "=" * 56)
    print("  JUNIPER CONSOLE SETUP - GUI")
    print(f"  Server running at: {url}")
    print("  Press Ctrl+C to stop.")
    print("  " + "=" * 56)
    print()

    log(f"Web server started at {url}", "PASS")

    # Auto-connect if COM port specified
    if args.com:
        connect_serial(args.com, args.baud)

    # Launch browser
    if not args.no_browser:
        webbrowser.open(url)

    # Start HTTP server
    server = HTTPServer(("127.0.0.1", args.port), RequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down...")
    finally:
        disconnect_serial()
        server.server_close()
        print("[INFO] Server stopped.")


if __name__ == "__main__":
    main()
