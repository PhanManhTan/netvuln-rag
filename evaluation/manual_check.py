"""Select and read saved evaluation answers in the terminal. No API calls."""

from __future__ import annotations

import argparse
import json
import random
import shutil
import textwrap
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evaluation.metrics import SCORER_VERSION, score_record, summarize
from evaluation.performance import PERFORMANCE_FIELDS, RUN_PERFORMANCE_FIELDS, format_performance, summarize_performance
from rag.identifiers import find_cve_ids


MODE_LABELS = {"llm_only": "B0 - LLM only", "llm_document": "B1 - Documents", "llm_raw": "B1 - Raw NVD", "llm_bm25": "BM25", "rag": "B2 - RAG"}
SHORT_LABELS = {"llm_only": "B0", "llm_document": "B1", "llm_raw": "B1 Raw", "llm_bm25": "BM25", "rag": "B2"}
PAGE_SIZE = 15
TASK_CRITERIA = {
    "version_inventory": "Return the complete CVE set for the requested version; avoid missing or extra CVEs and match the expected verdict.",
    "cve_version_check": "Identify the requested CVE and give the correct affected/not affected/insufficient evidence verdict for the version. Review platform and configuration conditions separately.",
    "vulnerability_detail": "Identify the correct CVE and match reference claims about impact, affected conditions, severity and remediation. Content correctness requires evidence review.",
    "semantic": "Return the complete CVE set matching the requested weakness or condition. Review whether the explanation answers the actual question.",
}


def read_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows, seen = [], set()
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            raise ValueError(f"Invalid JSON: {path}:{number}") from exc
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or row["id"] in seen:
            raise ValueError(f"Missing or duplicate question ID: {path}:{number}")
        seen.add(row["id"])
        rows.append(row)
    return rows


@dataclass
class SavedRun:
    path: Path
    model: str | None
    modes: list[str]
    questions: list[dict[str, Any]]
    answers: dict[str, dict[str, dict[str, Any]]]


def load_run(path: Path) -> SavedRun:
    metadata_path = path / "run.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.exists() else {}
    if not isinstance(metadata, dict):
        raise ValueError("run.json must contain a JSON object")
    modes = metadata.get("modes") or [mode for mode in MODE_LABELS if (path / f"{mode}_results.jsonl").exists()]
    if not isinstance(modes, list) or not modes or any(not isinstance(mode, str) or mode not in MODE_LABELS for mode in modes) or len(set(modes)) != len(modes):
        raise ValueError("No valid evaluation modes found")
    answers = {mode: {row["id"]: row for row in read_rows(path / f"{mode}_results.jsonl")} for mode in modes}
    questions_path = path / "reviewed_questions.jsonl"
    if not questions_path.exists():
        questions_path = path / "questions.jsonl"
    questions = {row["id"]: row for row in read_rows(questions_path)}
    for rows in answers.values():
        for identifier, row in rows.items():
            questions.setdefault(identifier, row)
    if not questions:
        raise ValueError("This run has no saved questions or answers")
    return SavedRun(path, metadata.get("model"), modes, list(questions.values()), answers)


def discover_runs(root: Path) -> list[Path]:
    return sorted(
        (path.parent for path in root.rglob("run.json") if (path.parent / "questions.jsonl").exists()),
        key=lambda path: (path / "run.json").stat().st_mtime_ns,
        reverse=True,
    )


def print_text(text: Any, width: int) -> None:
    for line in str(text or "").splitlines():
        print(textwrap.fill(line, width=width, replace_whitespace=False, drop_whitespace=False, break_long_words=False, break_on_hyphens=False) if line else "")


def display_width(text: str) -> int:
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in {"W", "F"} else 1 for c in text)


def wrap_cell(value: Any, width: int) -> list[str]:
    """Wrap complete cells without dropping long CVE IDs, URLs or Unicode text."""
    result = []
    for paragraph in unicodedata.normalize("NFC", str(value)).split("\n"):
        line = ""
        for word in paragraph.split():
            if line and display_width(line + " " + word) <= width:
                line += " " + word
                continue
            if line:
                result.append(line)
                line = ""
            for character in word:
                if line and display_width(line + character) > width:
                    result.append(line)
                    line = ""
                line += character
        result.append(line)
    return result


def print_table(headers: list[str], rows: list[list[str]], width: int, first_width: int | None = None) -> None:
    count = len(headers)
    available = max(count * 3, width - count * 3 - 1)
    if first_width is not None:
        first_width = min(first_width, available - (count - 1) * 3)
        base, extra = divmod(available - first_width, count - 1)
        widths = [first_width] + [base + (i < extra) for i in range(count - 1)]
    else:
        base, extra = divmod(available, count)
        widths = [base + (i < extra) for i in range(count)]

    def rule(left: str, middle: str, right: str) -> None:
        print(left + middle.join("─" * (size + 2) for size in widths) + right)

    def cells(values: list[str]) -> None:
        wrapped = [wrap_cell(value, size) for value, size in zip(values, widths)]
        for line in range(max(map(len, wrapped))):
            parts = [lines[line] if line < len(lines) else "" for lines in wrapped]
            print("│ " + " │ ".join(part + " " * max(0, size - display_width(part)) for part, size in zip(parts, widths)) + " │")

    rule("┌", "┬", "┐")
    cells(headers)
    for row in rows:
        rule("├", "┼", "┤")
        cells(row)
    rule("└", "┴", "┘")


def comparison_data(run: SavedRun, index: int) -> tuple[set[str], list[dict[str, Any]]]:
    item = run.questions[index]
    expected = set(find_cve_ids("\n".join(item.get("expected_cves") or [])))
    outputs = []
    for mode in run.modes:
        row = run.answers[mode].get(item["id"])
        status = (row.get("predicted_status") if row.get("review_correction") else row.get("verdict") or row.get("predicted_status")) if row else None
        failed = row is not None and (row.get("error") is not None or bool(row.get("output_error")) or row.get("predicted_status") == "error" or status == "error")
        explicit = row is not None and isinstance(row.get("asserted_cves"), list)
        cves = set()
        scored = None
        reviews = {}
        if row and not failed:
            effective = {**row, "mode": mode, **{field: item[field] for field in ("expected_cves", "expected_status", "expected_source_urls") if field in item}}
            scored = score_record(effective, None)
            status = scored["scored_status"]
            cves = set(scored["predicted_cves"])
            if row.get("manual_review"):
                reviews = summarize([effective], None)
        outputs.append({"mode": mode, "row": row, "status": status, "failed": failed, "explicit": explicit, "cves": cves, "scored": scored, "reviews": reviews})
    return expected, outputs


def cve_rows(expected: set[str], outputs: list[dict[str, Any]]) -> list[list[str]]:
    """One row per unique CVE, including extra identifiers from model answers."""
    identifiers = sorted(expected | set().union(*(output["cves"] for output in outputs)))
    rows = []
    for identifier in identifiers:
        cells = [identifier, "YES" if identifier in expected else "-"]
        for output in outputs:
            if output["row"] is None:
                cell = "NOT RUN"
            elif output["failed"]:
                cell = "ERROR"
            elif identifier in output["cves"]:
                cell = "YES" if identifier in expected else "+ EXTRA"
            else:
                cell = "! MISSING" if identifier in expected else "-"
            cells.append(cell)
        rows.append(cells)
    return rows


def evaluation_rows(item: dict[str, Any], outputs: list[dict[str, Any]]) -> list[list[str]]:
    """Expose current rule scores and saved human ratings; never call a judge."""
    names = [
        "CVE exact match", "Verdict match", "CVE + verdict", "CVE precision", "CVE recall", "CVE F1",
        "Evidence CVE recall", "Citation URL precision", "Expected URL hit", "Correct abstention",
        "Factual correctness", "Faithfulness", "Citation support", "LLM judge",
    ]

    def passed(value: bool) -> str:
        return "PASS" if value else "FAIL"

    def ratio(numerator: int, denominator: int) -> str:
        return f"{numerator / denominator:.1%} ({numerator}/{denominator})" if denominator else "N/A"

    columns = []
    for output in outputs:
        if output["row"] is None or output["failed"]:
            marker = "NOT RUN" if output["row"] is None else "ERROR"
            columns.append([marker] * (len(names) - 1) + ["NOT RUN"])
            continue
        scored = output["scored"]
        tp, fp, fn = (scored[key] for key in ("true_positive", "false_positive", "false_negative"))
        ratings = []
        for field in ("factual_correctness", "faithfulness", "citation_support"):
            value = output["reviews"].get(f"manual_{field}")
            ratings.append(passed(bool(value)) + " (human)" if value is not None else "NOT REVIEWED")
        has_verdict = bool(item.get("expected_status"))
        f1_denominator = 2 * tp + fp + fn
        columns.append([
            passed(scored["cve_exact_match"]),
            passed(scored["status_correct"]) if has_verdict else "N/A",
            passed(scored["cve_and_status_correct"]) if has_verdict else "N/A",
            ratio(tp, tp + fp), ratio(tp, tp + fn), f"{2 * tp / f1_denominator:.1%}" if f1_denominator else "N/A",
            ratio(scored["evidence_cve_hits"], scored["evidence_cve_expected"]),
            ratio(scored["valid_citation_count"], scored["citation_count"]),
            passed(scored["citation_covered"]) if scored["citation_required"] else "N/A",
            passed(scored["correct_abstention"]) if item.get("expected_status") == "insufficient_evidence" else "N/A",
            *ratings, "NOT RUN",
        ])
    return [[name, *[column[index] for column in columns]] for index, name in enumerate(names)]


def show_evaluation(item: dict[str, Any], outputs: list[dict[str, Any]], width: int) -> None:
    print(f"\nPER-QUESTION EVALUATION — scorer {SCORER_VERSION}")
    criterion = TASK_CRITERIA.get(item.get("question_type"), "Match the expected CVE set and verdict; check answer content against the reference sources.")
    print_text("Task criteria: " + criterion, width)
    print_table(["Criterion", *[SHORT_LABELS[output["mode"]] for output in outputs]], evaluation_rows(item, outputs), width, first_width=23)
    print_text("Rule checks measure agreement with saved labels. Citation URL matching does not verify claim support. N/A means an undefined denominator or inapplicable criterion.", width)
    print_text("Factual correctness, faithfulness and citation support show saved human reviews only. Unreviewed answers remain NOT REVIEWED. No LLM judge is configured or called.", width)
    for output in outputs:
        if output["reviews"].get("manual_reviewed_questions"):
            review = output["row"]["manual_review"]
            print_text(f"{SHORT_LABELS[output['mode']]} human review: {review['reviewed_by']} | {review['reviewed_at']} | {review.get('notes') or 'No review notes saved.'}", width)


def usage_rows(outputs: list[dict[str, Any]], *, overview: bool = False) -> list[list[str]]:
    fields = RUN_PERFORMANCE_FIELDS if overview else PERFORMANCE_FIELDS
    columns = []
    for output in outputs:
        rows = output["rows"] if overview else [output["row"]] if output["row"] is not None else []
        if not rows:
            columns.append(["NOT RUN"] * len(fields))
            continue
        usage = summarize_performance(rows)
        columns.append([format_performance(usage, key) for key, _ in fields])
    return [[label, *[column[index] for column in columns]] for index, (_, label) in enumerate(fields)]


def show_usage(outputs: list[dict[str, Any]], width: int, *, overview: bool = False) -> None:
    print("\nLLM EFFICIENCY — main system metrics" + (" (whole saved run)" if overview else " (this question)"))
    print_table(["Metric", *[SHORT_LABELS[output["mode"]] for output in outputs]], usage_rows(outputs, overview=overview), width, first_width=23)
    print_text("Totals include retries and failed/filtered responses with recorded usage. Token suffixes show reporting calls when counts are partial. NOT RECORDED means missing logs/counts; explicit zero-call responses use 0 tokens.", width)
    print_text("LLM time includes network time and excludes retrieval and pacing. TTFT measures time to the first output text delta in streaming runs. Observed output tok/s includes request overhead. Reasoning/cached tokens are already included in provider totals. Monetary cost is not recorded.", width)
    if overview:
        print_text("Totals use responses with request logs. Mean tokens/question requires complete total-token counts for every saved response, including zero-call responses. Latency percentiles use recorded attempts with linear interpolation; this table covers the whole saved run, including failed and unpaired responses.", width)


def show_run_usage(run: SavedRun, width: int) -> None:
    show_usage([{"mode": mode, "rows": list(run.answers[mode].values())} for mode in run.modes], width, overview=True)


def show_question(run: SavedRun, index: int, width: int = 100) -> None:
    item = run.questions[index]
    expected, outputs = comparison_data(run, index)
    labels = [SHORT_LABELS[mode] for mode in run.modes]
    print("\n" + "=" * width)
    print(f"Question {index + 1}/{len(run.questions)} | {item['id']}")
    print_text(item.get("question", ""), width)
    print(f"System answer: saved reference labels ({item.get('review_status') or 'draft'})")
    print_text(" | ".join(MODE_LABELS[mode] for mode in run.modes), width)
    verdict = item.get("expected_status")
    statuses, matches, methods, latencies = [], [], [], []
    for output in outputs:
        row = output["row"]
        unavailable = "NOT RUN" if row is None else "ERROR" if output["failed"] else None
        statuses.append((unavailable or output["status"] or "N/A").replace("_", " "))
        matches.append(unavailable or ("N/A" if not verdict or not output["status"] else "OK" if output["status"] == verdict else "! DIFF"))
        methods.append(unavailable or ("asserted_cves" if output["explicit"] else "Legacy heuristic"))
        latency = row.get("latency_seconds") if row else None
        latencies.append(f"{latency:.2f}s" if isinstance(latency, (int, float)) else "N/A")
    print_table(["Field", "System", *labels], [
        ["Verdict", (verdict or "N/A").replace("_", " "), *statuses],
        ["Verdict match", "Reference", *matches],
        ["CVE source", "Expected CVEs", *methods],
        ["Pipeline latency", "-", *latencies],
    ], width, first_width=14)
    show_usage(outputs, width)
    print("\nCVE COMPARISON — one CVE per row")
    matrix = cve_rows(expected, outputs)
    if matrix:
        first_width = max(17, max(display_width(row[0]) for row in matrix))
        print_table(["CVE", "System", *labels], matrix, width, first_width=first_width)
    else:
        print("No expected or returned CVEs.")
    print_text("YES = present and expected | ! MISSING = expected but absent | + EXTRA = outside the system answer | - = absent", width)
    if any(output["row"] and not output["explicit"] and not output["failed"] for output in outputs):
        print_text("Legacy outputs: CVE assertions use the current conclusion-aware heuristic; abstention-only repetitions are excluded. This can differ from the original run's older scores.", width)
    for output in outputs:
        if output["failed"]:
            print_text(f"{SHORT_LABELS[output['mode']]} error: {output['row'].get('error') or output['row'].get('output_error') or 'Failed response'}", width)
    show_evaluation(item, outputs, width)
    print("\nFULL ANSWERS AND SOURCES")
    show_answers(run, index, width)


def show_answers(run: SavedRun, index: int, width: int = 100) -> None:
    item = run.questions[index]
    reference = item.get("reference_answer") or "No reference answer text saved. Use the expected verdict, CVEs and sources."
    if item.get("reference_claims"):
        reference += "\n\nReference claims:\n" + "\n".join(item["reference_claims"])
    texts = [reference]
    sources = ["Sources:\n" + ("\n".join(item.get("expected_source_urls") or []) or "None saved")]
    for mode in run.modes:
        row = run.answers[mode].get(item["id"])
        texts.append((row.get("answer") or "No answer text saved.") if row is not None else "No saved response for this mode.")
        urls = list(dict.fromkeys(c["url"] for c in (row.get("citations") or [] if row else []) if c.get("url")))
        sources.append("Sources:\n" + ("\n".join(urls) or "None saved"))
    print_table(["System answer", *[SHORT_LABELS[mode] for mode in run.modes]], [texts, sources], width)


def list_questions(run: SavedRun, indices: list[int], page: int, width: int) -> None:
    pages = max(1, (len(indices) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = max(0, min(page, pages - 1))
    print(f"\n{len(indices)} questions | Page {page + 1}/{pages}")
    for index in indices[page * PAGE_SIZE:(page + 1) * PAGE_SIZE]:
        item = run.questions[index]
        count = sum(item["id"] in rows for rows in run.answers.values())
        label = f"{index + 1:>3}. [{count}/{len(run.modes)} mode] {item.get('question', item['id'])}"
        print(textwrap.shorten(" ".join(label.split()), width=width, placeholder="…"))
    if pages > 1:
        print(f"Use l 2, l 3, ... for other pages ({pages} total).")


def browse(run: SavedRun, width: int | None = None) -> int:
    width = width or max(60, shutil.get_terminal_size((100, 24)).columns)
    print(f"\nRun: {run.path}\nModel: {run.model or 'N/A'}")
    show_run_usage(run, width)
    indices = list(range(len(run.questions)))
    current = None
    list_questions(run, indices, 0, width)
    help_text = "Number/ID: select | n/p: next/previous | a: repeat answers | u: run LLM metrics | r: random | /text: search | l [page]: list | q: quit"
    print(help_text)
    while True:
        try:
            command = input("\nSelect > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        action = command.lower()
        if action in {"q", "quit", "exit"}:
            return 0
        if action in {"?", "help"}:
            print(help_text)
            continue
        if action == "u":
            show_run_usage(run, width)
            continue
        if action == "a":
            if current is None:
                print("Select a question first.")
            else:
                show_answers(run, current, width)
            continue
        if action == "l" or action.startswith("l "):
            page = action[2:].strip() if action != "l" else "1"
            if not page.isdecimal() or int(page) < 1:
                print("Enter l or l <page number>, for example l 2.")
                continue
            list_questions(run, indices, int(page) - 1, width)
            continue
        if command.isdecimal():
            selected = int(command) - 1
            if selected not in range(len(run.questions)):
                print(f"Select a number from 1 to {len(run.questions)}.")
                continue
            current = selected
        elif action in {"n", "p", ""}:
            if not indices:
                print("No matching questions. Enter / to reset the search.")
                continue
            position = indices.index(current) if current in indices else (-1 if action != "p" else len(indices))
            position += -1 if action == "p" else 1
            if position < 0 or position >= len(indices):
                print("End of the list. Select another number or enter l.")
                continue
            current = indices[position]
        elif action == "r":
            candidates = [index for index in indices if index != current and any(run.questions[index]["id"] in rows for rows in run.answers.values())]
            if not candidates:
                print("No other answered questions in this list.")
                continue
            current = random.choice(candidates)
        else:
            exact = next((index for index, item in enumerate(run.questions) if item["id"] == command), None)
            if exact is not None:
                current = exact
            else:
                term = command.removeprefix("/").strip().casefold()
                indices = [index for index, item in enumerate(run.questions) if term in json.dumps({"question": item, "answers": [rows.get(item['id']) for rows in run.answers.values()]}, ensure_ascii=False).casefold()]
                list_questions(run, indices, 0, width)
                if len(indices) != 1:
                    continue
                current = indices[0]
        show_question(run, current, width)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", nargs="?", type=Path, help="Saved run directory; omit to select a run")
    parser.add_argument("--width", type=int, help="Table width; defaults to your terminal width")
    args = parser.parse_args()
    if args.width is not None and args.width < 60:
        parser.error("--width must be at least 60")
    try:
        run_dir = args.run_dir
        if run_dir is None:
            from config.settings import get_settings

            root = get_settings().evaluation_dir
            runs = discover_runs(root)
            if not runs:
                parser.error(f"No saved runs in {root}. Pass a run directory explicitly.")
            print("Saved evaluation runs:")
            for number, path in enumerate(runs, 1):
                print(f"{number}. {path.relative_to(root)}")
            while True:
                choice = input("Select run [Enter = 1, q = quit] > ").strip()
                if choice.lower() == "q":
                    return 0
                if not choice:
                    choice = "1"
                if choice.isdecimal() and 1 <= int(choice) <= len(runs):
                    run_dir = runs[int(choice) - 1]
                    break
                print(f"Select a number from 1 to {len(runs)}.")
        return browse(load_run(run_dir), args.width)
    except (EOFError, KeyboardInterrupt):
        print()
        return 0
    except (OSError, ValueError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
