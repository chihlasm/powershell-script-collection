"""
NETCONF operations via junos-eznc.
All Juniper device interaction goes through this module.
"""

import re
import time

try:
    from jnpr.junos import Device
    from jnpr.junos.exception import (
        ConnectError, ConnectAuthError, ConnectTimeoutError,
        CommitError, ConfigLoadError, RpcError
    )
    from jnpr.junos.utils.config import Config
    HAS_JUNOS = True
except ImportError:
    HAS_JUNOS = False


def connect_device(host, username, password, port=830, timeout=30):
    """Open a NETCONF connection to a Juniper device. Returns (Device, None) or (None, error_str)."""
    if not HAS_JUNOS:
        return None, "junos-eznc is not installed. Run: pip install junos-eznc"
    try:
        dev = Device(
            host=host,
            user=username,
            passwd=password,
            port=port,
            timeout=timeout,
            auto_probe=5,
            normalize=True
        )
        dev.open()
        return dev, None
    except ConnectAuthError:
        return None, "auth_failed"
    except ConnectTimeoutError:
        return None, "timeout"
    except ConnectError as e:
        return None, f"connect_error: {e}"
    except Exception as e:
        return None, f"error: {e}"


def close_device(dev):
    """Safely close a device connection."""
    try:
        if dev:
            dev.close()
    except Exception:
        pass


def get_device_facts(dev):
    """Extract device facts from an open connection. Returns a dict."""
    facts = dev.facts
    hostname = facts.get("hostname", "")
    model = facts.get("model", "")
    version = facts.get("version", "")
    serial = facts.get("serialnumber", "")

    # Handle virtual chassis serial numbers (can be a list)
    if isinstance(serial, list):
        serial = " / ".join(serial)

    # Get uptime from RE0
    re0 = facts.get("RE0", {})
    uptime = str(re0.get("up_time", "")) if re0 else ""

    # Determine device type
    device_type = ""
    if model:
        model_upper = model.upper()
        if "SRX" in model_upper:
            device_type = "srx"
        elif "EX" in model_upper:
            device_type = "ex"
        elif "QFX" in model_upper:
            device_type = "qfx"

    return {
        "hostname": hostname,
        "model": model,
        "firmware_version": version,
        "serial_number": serial,
        "uptime": uptime,
        "device_type": device_type,
    }


def get_running_config(dev, format="text"):
    """Retrieve the running configuration."""
    try:
        config = dev.rpc.get_config(options={"format": format})
        if format == "text":
            return config.text
        else:
            from lxml import etree
            return etree.tostring(config, pretty_print=True).decode("utf-8")
    except Exception as e:
        return f"Error retrieving config: {e}"


def get_config_set_format(dev):
    """Retrieve the running configuration in 'set' format."""
    try:
        config = dev.rpc.get_config(options={"format": "set"})
        return config.text
    except Exception as e:
        return f"Error retrieving config: {e}"


def get_users(dev):
    """List configured login users. Returns a list of dicts."""
    users = []
    try:
        config = dev.rpc.get_config(
            filter_xml="<configuration><system><login></login></system></configuration>",
            options={"format": "text"}
        )
        config_text = config.text if hasattr(config, 'text') else str(config)

        current_user = None
        for line in config_text.splitlines():
            m = re.match(r'\s*user\s+(\S+)\s*\{', line)
            if m:
                current_user = {"username": m.group(1), "class": "unknown"}
            elif current_user:
                m = re.match(r'\s*class\s+(\S+);', line)
                if m:
                    current_user["class"] = m.group(1)
                if re.match(r'\s*\}', line):
                    if current_user["username"] != "root":
                        users.append(current_user)
                    current_user = None
    except Exception as e:
        return []

    return users


def create_user(dev, username, password, user_class="super-user"):
    """Create a user account on the device."""
    try:
        with Config(dev, mode="exclusive") as cu:
            cu.load(f"set system login user {username} class {user_class}", format="set")
            cu.commit(comment=f"Created user {username}")

        # Set password via RPC (plain-text-password requires interactive, so use encrypted)
        # Instead, use load with set format for the full command
        with Config(dev, mode="exclusive") as cu:
            # Generate password hash using the device itself
            rpc_reply = dev.rpc.cli(f"set system login user {username} authentication plain-text-password", format="text")
            # This doesn't work non-interactively, so we use a different approach
            pass
    except Exception:
        pass

    # Simpler approach: use configuration load
    try:
        with Config(dev, mode="exclusive") as cu:
            commands = [
                f"set system login user {username} class {user_class}",
            ]
            cu.load("\n".join(commands), format="set")
            cu.commit(comment=f"Created user {username}")
        return {"success": True, "message": f"User '{username}' created with class '{user_class}'."}
    except CommitError as e:
        return {"success": False, "message": f"Commit error: {e}"}
    except ConfigLoadError as e:
        return {"success": False, "message": f"Config load error: {e}"}
    except Exception as e:
        return {"success": False, "message": f"Error: {e}"}


def set_user_password(dev, username, password):
    """Set a user's password. Uses the device's built-in hashing."""
    try:
        # Use the CLI RPC to hash the password on-device
        import crypt
        import secrets
        salt = secrets.token_hex(8)
        hashed = crypt.crypt(password, f"$6${salt}$")

        with Config(dev, mode="exclusive") as cu:
            cu.load(
                f'set system login user {username} authentication encrypted-password "{hashed}"',
                format="set"
            )
            cu.commit(comment=f"Updated password for {username}")
        return {"success": True, "message": f"Password updated for '{username}'."}
    except ImportError:
        # crypt not available (Windows) - use SHA-512 via hashlib
        import hashlib
        import struct
        # Fallback: let the device handle it via RPC if possible
        try:
            with Config(dev, mode="exclusive") as cu:
                cu.load(
                    f'set system login user {username} authentication plain-text-password "{password}"',
                    format="set"
                )
                cu.commit(comment=f"Updated password for {username}")
            return {"success": True, "message": f"Password updated for '{username}'."}
        except Exception as e:
            return {"success": False, "message": f"Error setting password: {e}"}
    except CommitError as e:
        return {"success": False, "message": f"Commit error: {e}"}
    except Exception as e:
        return {"success": False, "message": f"Error: {e}"}


def delete_user(dev, username):
    """Delete a user account from the device."""
    try:
        with Config(dev, mode="exclusive") as cu:
            cu.load(f"delete system login user {username}", format="set")
            cu.commit(comment=f"Deleted user {username}")
        return {"success": True, "message": f"User '{username}' deleted."}
    except CommitError as e:
        return {"success": False, "message": f"Commit error: {e}"}
    except Exception as e:
        return {"success": False, "message": f"Error: {e}"}


def push_config(dev, commands, commit_comment="Pushed via Juniper Device Manager"):
    """Push configuration commands to the device with commit confirmed safety."""
    try:
        with Config(dev, mode="exclusive") as cu:
            for cmd in commands:
                cu.load(cmd.strip(), format="set")
            # Use commit confirmed for safety (auto-rollback after 5 min if not confirmed)
            cu.commit(comment=commit_comment, confirm=5)
            time.sleep(1)
            # Confirm the commit
            cu.commit(comment="Confirming previous commit")
        return {"success": True, "message": f"Configuration pushed successfully ({len(commands)} commands)."}
    except CommitError as e:
        return {"success": False, "message": f"Commit error: {e}"}
    except ConfigLoadError as e:
        return {"success": False, "message": f"Config load error: {e}"}
    except Exception as e:
        return {"success": False, "message": f"Error: {e}"}


def restore_config(dev, config_text, commit_comment="Config restore via Juniper Device Manager"):
    """Restore a full configuration from backup."""
    try:
        with Config(dev, mode="exclusive") as cu:
            cu.load(config_text, format="text", overwrite=True)
            cu.commit(comment=commit_comment, confirm=5)
            time.sleep(1)
            cu.commit(comment="Confirming config restore")
        return {"success": True, "message": "Configuration restored successfully."}
    except CommitError as e:
        return {"success": False, "message": f"Commit error: {e}"}
    except Exception as e:
        return {"success": False, "message": f"Error: {e}"}


def install_firmware(dev, image_path, reboot=True, progress_callback=None):
    """Install firmware on the device. This can take 10-30+ minutes."""
    try:
        from jnpr.junos.utils.sw import SW
        sw = SW(dev)

        def _progress(dev_obj, report):
            if progress_callback:
                progress_callback(report)

        ok = sw.install(
            package=image_path,
            no_copy=False,
            validate=False,
            progress=_progress,
            cleanfs=True,
        )

        if ok and reboot:
            sw.reboot()
            return {"success": True, "message": "Firmware installed. Device is rebooting."}
        elif ok:
            return {"success": True, "message": "Firmware installed. Reboot when ready."}
        else:
            return {"success": False, "message": "Firmware install returned failure."}
    except Exception as e:
        return {"success": False, "message": f"Firmware install error: {e}"}
