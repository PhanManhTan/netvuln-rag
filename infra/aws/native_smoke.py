"""Install two exact nginx versions directly on Linux and verify loopback HTTP.

This is a local installation test, not a sixteen-machine AWS/CVE benchmark.
No Docker, system services, SSH configuration or routing changes are involved.
"""

from __future__ import annotations

import argparse
import contextlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener

from infra.aws.build import build_target
from infra.aws.catalog import ROOT, load_lock, load_manifest, target_by_id


def run_native(directory: Path, report_path: Path) -> dict:
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    manifest = load_manifest()
    lock = load_lock(manifest)
    report = {"schema_version": 1, "scope": "native_nginx_installation_and_loopback_http_only",
              "created_at": datetime.now(timezone.utc).isoformat(), "root": str(directory), "results": [], "complete": False}
    processes = []
    opener = build_opener(ProxyHandler({}))
    try:
        for identity, port in (("NGINX-A", 18080), ("NGINX-B", 18081)):
            target = target_by_id(manifest, identity)
            with socket.socket() as probe_socket:
                probe_socket.bind(("127.0.0.1", port))
            work = directory / "build-work" / identity
            log_path = directory / f"{identity}.build.log"
            with log_path.open("w") as log, contextlib.redirect_stdout(log):
                # Compiler subprocesses inherit OS stdout, not redirect_stdout's Python object.
                saved_stdout, saved_stderr = os.dup(1), os.dup(2)
                try:
                    sys.stdout.flush()
                    os.dup2(log.fileno(), 1)
                    os.dup2(log.fileno(), 2)
                    build = build_target(target, manifest, lock, ROOT.parents[1] / "artifacts/aws/sources", work,
                                         directory / "products", native_local=True)
                    log.flush()
                finally:
                    os.dup2(saved_stdout, 1)
                    os.dup2(saved_stderr, 2)
                    os.close(saved_stdout)
                    os.close(saved_stderr)
            # Delete only this command's temporary compilation tree after installation.
            shutil.rmtree(work)
            state = directory / identity
            state.mkdir()
            web = state / "www"
            web.mkdir()
            (web / "index.html").write_text(f"{identity} nginx/{target['version']}\n")
            config = state / "nginx.conf"
            config.write_text(f"daemon off;\nmaster_process off;\npid {state}/nginx.pid;\nerror_log {state}/error.log;\nevents {{ worker_connections 64; }}\nhttp {{ access_log off; server {{ listen 127.0.0.1:{port}; root {web}; }} }}\n")
            runtime_log = (state / "runtime.log").open("w")
            try:
                process = subprocess.Popen([build["binary"], "-c", str(config)], stdin=subprocess.DEVNULL, stdout=runtime_log,
                                           stderr=subprocess.STDOUT, start_new_session=True)
            finally:
                runtime_log.close()
            processes.append(process)
            endpoint = f"http://127.0.0.1:{port}/"
            body = None
            for _ in range(40):
                if process.poll() is not None:
                    raise RuntimeError(f"Native nginx exited: inspect {state / 'runtime.log'}")
                try:
                    with opener.open(endpoint, timeout=2) as response:
                        body = response.read().decode().strip()
                    break
                except (URLError, OSError):
                    time.sleep(0.25)
            if body != f"{identity} nginx/{target['version']}":
                raise ValueError("Native HTTP response does not match the installed target")
            report["results"].append({"device_id": identity, "status": "passed", "build": build, "pid": process.pid,
                                      "endpoint": endpoint, "response": body, "build_log": str(log_path), "config": str(config)})
            print(f"Installed and serving: {identity} {target['version']} at {endpoint}", flush=True)
        report["complete"] = True
    except Exception:
        for process in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
        raise
    finally:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("/tmp/netvuln-native") / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ"))
    parser.add_argument("--report", type=Path, default=Path("artifacts/aws/native-smoke.json"))
    args = parser.parse_args()
    report = run_native(args.directory, args.report)
    print(json.dumps({"complete": report["complete"], "report": str(args.report), "directory": str(args.directory)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
