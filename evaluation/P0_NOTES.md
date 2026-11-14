# P0 update — 2026-11-09

Base revision: `aebca53` from `origin/main`. Local environment-example edits were preserved.

## Implemented

- Shared JSON answer envelope with a separate verdict, explanation and asserted CVE list; provider-independent validation and explicit legacy fallback metadata.
- Raw model output, rejected identifiers/citations and contradictory version conclusions retained for audit. Filtered responses cannot receive correct-abstention credit.
- Scorer 2.0: conclusion-aware legacy parser, explicit assertion scoring, URL-overlap naming, per-group denominators, macro scores, confusion matrix and separately reviewed factual/faithfulness/citation-support metrics.
- Conservative CPE normalization: unsupported logical, platform or component constraints remain limitations rather than unconditional affected rules. Exact-query membership remains explicitly scoped to the saved NVD query.
- Draft/approved/rejected gold metadata, evidence and approval provenance validation, and `evaluation.run --require-reviewed`.
- Deterministic candidate selection, alternate wording, natural-language weakness questions and complete CWE-membership gold sets.
- Offline review packets, approved-dataset export and rescoring with source hashes and original-value trails. See [README](README.md#review-and-freeze-questions-offline).

## Local artifacts prepared

- [121-question compact draft](../artifacts/evaluation/p0-review/questions.compact.draft.jsonl): 57 version checks, 16 inventories, 24 details and 24 semantic questions. All remain draft; there are still no independently approved not-affected or source-conflict cases.
- [Compact review packet](../artifacts/evaluation/p0-review/questions.compact.review.json): source evidence and editable review slots, without fabricated approvals.
- [First-run review packet](../artifacts/evaluation/p0-review/first-run.review.json): 129 planned questions and 151 saved responses across the three modes, including the failed request.
- [Offline rescore](../artifacts/evaluation/p0-review/first-run.rescored/summary.json): scorer 2.0 applied to the original 50 completed pairs, with zero new model calls. The run is still incomplete. Changed scores reflect a different scorer applied to existing outputs, not an improvement to model performance or verification of draft labels.

These artifacts are under the repository's ignored evaluation-output directory; regenerate them with the documented CLI when moving to another checkout.

## Source discrepancy requiring review

The saved OpenSSH query for `9.8p1` includes `CVE-2024-6387` and the old dataset labels it affected. The saved CVE configuration includes an OpenSSH range with `versionEndIncluding: 9.8`. In contrast, the [OpenSSH 9.8 release notes](https://www.openssh.org/txt/release-9.8) describe the fix and give the regression's affected Portable versions as 8.5p1–9.7p1; the [original Qualys advisory](https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt) identifies CVE-2024-6387 and places the fixed boundary at 9.8p1.

Keep the original snapshot for reproducibility. A question asking what the saved NVD query returned and a question asking whether upstream Portable OpenSSH is affected need distinct labels and evidence. Do not silently overwrite a snapshot-membership label with an upstream applicability conclusion. Review the inventory and direct-check cases together before approving deployment-impact claims.

## Validation and remaining data work

- `python -m pytest -q`: **163 passed**.
- `git diff --check`: clean.
- Built the compact draft from the published snapshot's pinned raw runs and checked all 121 questions against the parser: no product/intent mismatches.
- Exercised packet export and rescoring on the actual saved run; originals were retained and no generation requests were made.

Human/source review of all candidate labels is still required. Structured output validates format, not factual truth. Legacy outputs still use a heuristic unless explicitly reviewed. The existing processed snapshot and Qdrant collection were left in place: normalize/chunk again and build a matching index to apply the new data safeguards to served evidence. Global crawl, resume and atomic index publication remain separate P1 work.
