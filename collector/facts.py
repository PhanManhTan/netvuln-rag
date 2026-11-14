"""One-shot facts for Ansible/SSH. No daemon, listener, token or push transport."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from collector.agent import collect


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/netvuln/facts.json"))
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    snapshot = collect(config)
    snapshot["network"]["collection_transport"] = config.get("collection_transport", "ansible_ssh")
    print(json.dumps(snapshot, ensure_ascii=False))
    return 0 if snapshot["collection_status"] == "collected" else 1


if __name__ == "__main__":
    raise SystemExit(main())
