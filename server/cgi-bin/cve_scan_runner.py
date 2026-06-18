#!/usr/bin/env python3
"""Standalone entry point for the background fleet CVE scan.

Spawned by ``handle_cve_scan`` via ``subprocess.Popen(start_new_session=True)``
so the scan runs as a genuinely independent process — never inline in the web
worker, never sharing its client socket or DB connection. This is more robust
across deployment models (SCGI prefork worker, fcgiwrap CGI) than fork()ing the
request handler: that path had to hand-close every inherited fd and, when
``os.fork()`` failed under load, silently fell back to running the whole fleet
scan *inline*, blocking the request until it finished (the "Scan all devices
freezes the UI" bug).

Usage:  cve_scan_runner.py <actor> [<device_id>]
        (an empty/omitted device_id scans the whole fleet)
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import api  # noqa: E402 — re-imports the app to get a fresh process state


def main():
    actor = sys.argv[1] if len(sys.argv) > 1 else 'system'
    target = (sys.argv[2].strip() if len(sys.argv) > 2 else '') or None
    api._cve_scan_worker(actor, target)


if __name__ == '__main__':
    main()
