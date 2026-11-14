"""One live OpenSSH case: Ansible facts -> snapshot -> LLM/RAG -> diagnostic scores.

Expected labels are derived from an independently pinned official CVE record and
observed source/build/configuration. They remain draft until independently reviewed.
This command neither crawls a corpus nor modifies the existing knowledge base.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import time
from urllib.request import Request, urlopen

import requests

from collector.agent import push
from collector.models import DeviceSnapshot
from collector.server import token_digest
from collector.store import SnapshotStore
from config.settings import get_settings
from evaluation.client import BenchmarkClient
from evaluation.metrics import score_record
from evaluation.run import run_baseline, run_rag
from infra.aws.catalog import load_lock, load_manifest
from infra.aws.sources import sha256
from rag.generation.chatbot import RAGChatbot
from rag.identifiers import normalize_dashes


CVE = "CVE-2024-6387"
CVE_URL = f"https://cveawg.mitre.org/api/cve/{CVE}"
UPSTREAM_URL = "https://www.openssh.org/txt/release-9.8"


def answer_diagnostics(answer: str, evidence: str, question: str) -> dict:
    """Flag unsupported text claims; a clean result is not proof of full correctness."""
    text = normalize_dashes(answer)
    versions = re.compile(r"(?<![\w.])([0-9]+(?:\.[0-9A-Za-z]+)+)(?!\w|\.[0-9A-Za-z])")
    known = {value.lower() for value in versions.findall(evidence + "\n" + question)}
    proposed = set()
    for clause in re.split(r"(?<=[.!?])\s+|\n+", text):
        if re.search(r"nâng cấp|cập nhật|khuyến nghị|upgrade|patched|fixed version", clause, re.IGNORECASE):
            proposed.update(value.lower() for value in versions.findall(clause))
    mismatched_ranges = []
    for match in re.finditer(r"(?:từ|from)\s+([0-9]+\.[0-9]+p[0-9]+)\s+(?:trở\s+lên|onward|and later|or later)", text, re.IGNORECASE):
        mismatched_ranges.append({"claimed_lower": match.group(1), "claimed_upper": None,
                                  "official_lower": "8.5p1", "official_upper": "9.7p1"})
    return {"unsupported_recommendation_versions": sorted(proposed - known), "unbounded_range_conflicts": mismatched_ranges,
            "scope": "heuristic_diagnostics_not_complete_semantic_scoring"}


def audit_saved_pilot(directory: Path) -> dict:
    from rag.retrieval.retriever import Retriever
    settings = get_settings()
    summary = json.loads((directory / "summary.json").read_text())
    if sha256(settings.processed_manifest) != summary["corpus_manifest_sha256"]:
        raise ValueError("Corpus changed; cannot reconstruct evidence for this saved pilot")
    question = json.loads((directory / "questions.jsonl").read_text())["question"]
    retriever = Retriever(settings)
    context, sources = retriever.format_context(retriever.search(question, settings.top_k), max_chars=settings.context_max_chars)
    (directory / "retrieved-context.txt").write_text(context)
    (directory / "retrieved-sources.json").write_text(json.dumps(sources, indent=2) + "\n")
    results = {}
    for mode in ("llm_only", "rag"):
        row = json.loads((directory / f"{mode}_result.json").read_text())
        results[mode] = {"tuple_match": row["cve_and_status_correct"],
                         **answer_diagnostics(row["answer"], context if mode == "rag" else "", question)}
    result = {"schema_version": 1, "source": "official-cve.json and upstream-release-9.8.txt pinned before generation",
              "raw_results_modified": False, "whole_answer_accuracy": None, "results": results,
              "interpretation": "CVE/verdict agreement is narrower than whole-answer factual correctness. Flags require source audit and are not a formal reviewed metric."}
    (directory / "answer-diagnostics.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return result


def portable_version(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"([0-9]+)\.([0-9]+)p([0-9]+)", value)
    if not match:
        raise ValueError("Unsupported Portable OpenSSH version in source-backed pilot")
    return tuple(map(int, match.groups()))


def expected_case(snapshot: dict, cve_record: dict, pinned_source: str) -> dict:
    validated = DeviceSnapshot.model_validate(snapshot)
    software = [row for row in validated.software if row.product_id == "openssh" and row.component == "sshd"]
    if len(software) != 1:
        raise ValueError("Pilot needs exactly one observed sshd component")
    target = software[0]
    if target.version != "9.6p1" or target.evidence.get("source_sha256") != pinned_source:
        raise ValueError("Pilot binary must be built from the locked upstream 9.6p1 source")
    if not target.running or target.evidence.get("process_uid") != 0 or not target.binary_sha256:
        raise ValueError("Pilot needs a running standard root sshd with binary evidence")
    if not validated.network.get("libc", "").startswith("glibc ") or int(target.configuration.get("logingracetime", "0")) <= 0:
        raise ValueError("Published Linux/glibc and LoginGraceTime conditions were not established")
    if cve_record.get("cveMetadata", {}).get("cveId") != CVE or cve_record["cveMetadata"].get("state") != "PUBLISHED":
        raise ValueError("Official CVE record is missing or not published")
    matches = []
    for product in cve_record["containers"]["cna"].get("affected", []):
        if product.get("packageName") != "OpenSSH":
            continue
        for rule in product.get("versions", []):
            if rule.get("status") == "affected" and rule.get("version") == "8.5p1" and rule.get("lessThanOrEqual") == "9.7p1":
                matches.append(portable_version(rule["version"]) <= portable_version(target.version) <= portable_version(rule["lessThanOrEqual"]))
    if not matches or not all(matches):
        raise ValueError("Official record does not establish the pilot's affected version interval")
    return {"device_id": validated.device_id, "product_id": "openssh", "version": target.version, "cve": CVE,
            "verdict": "affected", "review_status": "draft_source_backed_not_human_approved",
            "basis": "Official upstream affected interval plus locked unpatched source, running root sshd, glibc and nonzero LoginGraceTime",
            "source_urls": [CVE_URL, UPSTREAM_URL, f"https://nvd.nist.gov/vuln/detail/{CVE}"],
            "limitation": "Affected software classification only; exploitation was not tested or established on this host."}


def collect_over_tls(snapshot: dict, state: Path) -> tuple[dict, subprocess.Popen]:
    state.mkdir(mode=0o700)
    cert, key = state / "collector.crt", state / "collector.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=pilot-collector", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", str(key), "-out", str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    key.chmod(0o600)
    with socket.socket() as port_probe:
        port_probe.bind(("127.0.0.1", 0))
        port = port_probe.getsockname()[1]
    agent_token, reader_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    software = snapshot["software"][0]
    registry = {snapshot["device_id"]: {"product_id": "openssh", "version": software["version"], "ip": "127.0.0.1", "token_sha256": token_digest(agent_token)}}
    configuration = {"storage_dir": str(state / "snapshots"), "devices": registry, "read_token_sha256": token_digest(reader_token)}
    config_path = state / "collector.json"
    config_path.write_text(json.dumps(configuration))
    config_path.chmod(0o600)
    with (state / "collector.log").open("w") as log:
        process = subprocess.Popen([sys.executable, "-m", "uvicorn", "collector.server:app_factory", "--factory", "--host", "127.0.0.1", "--port", str(port), "--ssl-certfile", str(cert), "--ssl-keyfile", str(key), "--no-access-log"],
                                   env={**os.environ, "COLLECTOR_CONFIG": str(config_path)}, stdout=log, stderr=subprocess.STDOUT)
    context = ssl.create_default_context(cafile=str(cert))
    base = f"https://127.0.0.1:{port}"
    for _ in range(80):
        if process.poll() is not None:
            raise RuntimeError("Local collector exited; inspect its log")
        try:
            with urlopen(base + "/health", context=context, timeout=2) as response:
                if response.status == 200:
                    break
        except OSError:
            time.sleep(0.1)
    try:
        push({"collector_url": base, "ca_file": str(cert), "token": agent_token}, snapshot)
        request = Request(base + "/v1/snapshot", headers={"Authorization": "Bearer " + reader_token})
        with urlopen(request, context=context, timeout=10) as response:
            received = json.load(response)
        if not received["complete"] or received["ready_devices"] != 1:
            raise ValueError("Collector did not establish a complete single-device snapshot")
        return received, process
    except Exception:
        process.terminate()
        process.wait(timeout=10)
        raise


def accept_ansible_snapshot(snapshot: dict, directory: Path) -> dict:
    if snapshot.get("network", {}).get("collection_transport") not in {"ansible_local", "ansible_ssh"}:
        raise ValueError("Default pilot requires observed Ansible facts; recollect with the playbook")
    registry = {snapshot["device_id"]: {"product_id": "openssh", "version": "9.6p1", "ip": "127.0.0.1"}}
    store = SnapshotStore(directory, registry)
    identity = store.save(DeviceSnapshot.model_validate(snapshot))
    received = store.freeze(max_age_seconds=900)
    if not received["complete"] or received["snapshots"][0]["snapshot_id"] != identity:
        raise ValueError("Observed Ansible snapshot is incomplete or differs from the registered pilot")
    return received


def run_pilot(snapshot_path: Path, directory: Path, provider: str | None = None, transport: str = "ansible") -> dict:
    directory.mkdir(parents=True, exist_ok=False)
    raw_snapshot = json.loads(snapshot_path.read_text())
    snapshot = DeviceSnapshot.model_validate(raw_snapshot).model_dump(mode="json")
    age = (datetime.now(timezone.utc) - DeviceSnapshot.model_validate(snapshot).collected_at).total_seconds()
    if not -120 <= age <= 900:
        raise ValueError("Pilot snapshot must be fresh; collect it again before evaluating")
    cve_response = requests.get(CVE_URL, timeout=60)
    cve_response.raise_for_status()
    cve_record = cve_response.json()
    upstream = requests.get(UPSTREAM_URL, timeout=60)
    upstream.raise_for_status()
    (directory / "official-cve.json").write_bytes(cve_response.content)
    (directory / "upstream-release-9.8.txt").write_bytes(upstream.content)
    pin = load_lock(load_manifest())["sources"]["openssh-9.6p1"]["sha256"]
    expected = expected_case(snapshot, cve_record, pin)
    # Check the observed binary independently of saved agent metadata before either model sees it.
    if sha256(Path(snapshot["software"][0]["binary"])) != snapshot["software"][0]["binary_sha256"]:
        raise ValueError("Pilot binary changed after collection")
    listener = snapshot["network"]["listener"]
    host, port = listener.rsplit(":", 1)
    with socket.create_connection((host, int(port)), timeout=5) as connection:
        if not connection.recv(1024).decode().startswith("SSH-2.0-OpenSSH_9.6"):
            raise ValueError("Live SSH endpoint no longer matches the snapshot")
    collector = None
    if transport == "tls-demo":
        received, collector = collect_over_tls(snapshot, directory / "collector")
    else:
        received = accept_ansible_snapshot(snapshot, directory / "snapshots")
    try:
        (directory / "collector-snapshot.json").write_text(json.dumps(received, indent=2) + "\n")
        (directory / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")
        accepted = received["snapshots"][0]
        facts = {key: accepted[key] for key in ("device_id", "collected_at", "os", "software", "network")}
        question = (
            f"Trên thiết bị OPENSSH-A, OpenSSH 9.6p1 có thuộc phạm vi phần mềm bị ảnh hưởng bởi {CVE} không? "
            "Đối chiếu platform/cấu hình thu được, nêu giới hạn bằng chứng và nguồn nếu biết; phân biệt phân loại affected với chứng minh khai thác thành công.\n"
            "Thông tin máy từ collector:\n" + json.dumps(facts, ensure_ascii=False)
        )
        item = {"id": "native-openssh-9.6p1-cve-2024-6387", "product_id": "openssh", "question_type": "cve_version_check",
                "question": question, "expected_cves": [CVE], "expected_status": expected["verdict"],
                "expected_source_urls": expected["source_urls"], "review_status": "draft", "famous": False, "has_conflict": False,
                "notes": "Diagnostic single-device pilot; independent human gold review pending."}
        (directory / "questions.jsonl").write_text(json.dumps(item, ensure_ascii=False) + "\n")
        settings = get_settings()
        provider = provider or settings.llm_provider
        llm = BenchmarkClient(settings, request_interval=6 if provider == "groq" else 0, max_retries=2)
        chatbot = RAGChatbot(settings=settings, llm=llm)
        rows = []
        for mode in ("llm_only", "rag"):
            if rows and provider == "groq":
                # Pacing between modes is outside each question's measured latency.
                time.sleep(6)
            llm.attempts = []
            waited_before = llm.wait_seconds
            print(f"Pilot: {mode} using {provider}/{llm.model_name(provider)}", flush=True)
            row = run_baseline(item, llm, provider) if mode == "llm_only" else run_rag(item, chatbot, provider, settings.top_k, max_context_chars=settings.context_max_chars)
            row["llm_requests"] = llm.attempts
            row["pacing_wait_seconds"] = llm.wait_seconds - waited_before
            scored = score_record(row, None)
            rows.append(scored)
            (directory / f"{mode}_result.json").write_text(json.dumps(scored, ensure_ascii=False, indent=2) + "\n")
            print(f"Pilot {mode}: verdict={scored['scored_status']}, exact_case_match={scored['cve_and_status_correct']}, error={scored['error']}", flush=True)
        summary = {"schema_version": 1, "scope": "one_question_one_live_device_diagnostic_not_full_benchmark",
                   "gold_review_status": expected["review_status"], "question_count": 1, "provider": provider, "model": llm.model_name(provider),
                   "collector_complete": received["complete"], "snapshot_id": accepted["snapshot_id"], "expected": expected,
                   "collection_transport": snapshot["network"].get("collection_transport", "tls_demo") if transport == "ansible" else "tls_demo",
                   "source_hashes": {"cve_record": sha256(directory / "official-cve.json"), "upstream_release": sha256(directory / "upstream-release-9.8.txt")},
                   "corpus_manifest_sha256": sha256(settings.processed_manifest),
                   "whole_answer_accuracy": None,
                   "results": [{key: row.get(key) for key in ("mode", "scored_status", "predicted_cves", "cve_and_status_correct", "true_positive", "false_positive", "false_negative", "citation_count", "citation_covered", "latency_seconds", "error", "output_error")} for row in rows],
                   "limitations": ["One positive case cannot estimate model accuracy or recall across the proposal.", "Citation URL overlap is automatic; source-support/wording review remains pending.", "CVE existence/hallucination rate is not estimated from a one-CVE catalog.", "No Greenbone scan or exploit attempt was performed."]}
        (directory / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
        audit_saved_pilot(directory)
        return summary
    finally:
        if collector is not None:
            collector.terminate()
            collector.wait(timeout=10)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, default=Path("artifacts/aws/ansible-pilot/snapshot.json"))
    parser.add_argument("--transport", choices=("ansible", "tls-demo"), default="ansible", help="TLS demo is retained only to reproduce the earlier pilot")
    parser.add_argument("--output", type=Path, default=Path("artifacts/aws/pilot") / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ"))
    parser.add_argument("--provider")
    parser.add_argument("--audit-only", type=Path, help="Inspect a saved pilot without calling a model or changing its raw results")
    args = parser.parse_args()
    if args.audit_only:
        audit_saved_pilot(args.audit_only)
        return 0
    result = run_pilot(args.snapshot, args.output, args.provider, args.transport)
    print(json.dumps({"output": str(args.output), "collector_complete": result["collector_complete"], "results": result["results"]}, ensure_ascii=False, indent=2))
    return 0 if all(not row["error"] for row in result["results"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
