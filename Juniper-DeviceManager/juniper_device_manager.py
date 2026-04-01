"""
Juniper Device Manager - Entry Point
=====================================
Browser-based fleet management tool for Juniper EX/SRX devices via NETCONF.

Usage:
    python juniper_device_manager.py
    python juniper_device_manager.py --port 9090
    python juniper_device_manager.py --no-browser --db custom.db

Requirements:
    pip install junos-eznc
"""

import argparse
import os
import sys
import webbrowser
from http.server import HTTPServer

# Add script directory to path for sibling imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import db
from server import JuniperManagerHandler, log


def main():
    parser = argparse.ArgumentParser(description="Juniper Device Manager - Browser GUI")
    parser.add_argument("--port", type=int, default=8290, help="Web server port (default: 8290)")
    parser.add_argument("--no-browser", action="store_true", help="Don't auto-open browser")
    parser.add_argument("--db", type=str, default="", help="Custom database path")
    args = parser.parse_args()

    # Database path
    db_path = args.db or os.path.join(os.path.dirname(os.path.abspath(__file__)), "juniper_manager.db")
    db.init_db(db_path)

    url = f"http://localhost:{args.port}/"

    print()
    print("  " + "=" * 56)
    print("  JUNIPER DEVICE MANAGER")
    print(f"  Server running at: {url}")
    print(f"  Database: {db_path}")
    print("  Press Ctrl+C to stop.")
    print("  " + "=" * 56)
    print()

    log(f"Server started at {url}", "PASS")
    log(f"Database: {db_path}", "INFO")

    # Check for junos-eznc
    try:
        import jnpr.junos
        log(f"junos-eznc version: {jnpr.junos.__version__}", "INFO")
    except ImportError:
        log("WARNING: junos-eznc is not installed. Discovery and device operations will not work.", "WARN")
        log("Install with: pip install junos-eznc", "WARN")

    if not args.no_browser:
        webbrowser.open(url)

    server = HTTPServer(("127.0.0.1", args.port), JuniperManagerHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down...")
    finally:
        server.server_close()
        print("[INFO] Server stopped.")


if __name__ == "__main__":
    main()
