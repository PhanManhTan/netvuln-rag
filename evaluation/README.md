# Evaluation

The benchmark compares LLM-only (B0) and RAG (B2) using the same model and questions. With the default catalog, the builder generates draft questions and expected answers from the raw NVD snapshot.

## Build and review a dataset

After completing the NVD crawl, generate candidates.

```bash
python -m evaluation.build
```

| Question type | Draft answer |
| --- | --- |
| Version inventory | The CVE set returned for the requested version CPE |
| CVE/version check | `affected` for a matching CVE or `insufficient_evidence` for an adjacent-version case without a matching record |
| CVE detail | The CVE and source URL, plus the original description in `reference_answer` for reviewing the summary |
| CWE lookup | All CVEs in the product snapshot with the requested CWE. These questions exercise BM25 and Qdrant retrieval. |

Use `--product` to select a product and `--run` to pin its raw run. Use `--checks-per-version`, `--details-per-product`, and `--semantic-per-product` to cap candidate counts. The default output is `$ARTIFACTS_DIR/evaluation/questions.jsonl`. Use `--output` to choose another file.

Check the expected CVEs, affected conditions, and citations against the original records. For natural-language descriptions, rewrite candidate CWE questions and verify the full set of matching CVEs. Select and freeze the reviewed dataset before benchmarking. See [questions.sample.jsonl](questions.sample.jsonl) for the JSONL format.

## Run the benchmark

Process the same raw runs used to build the dataset. Index the processed chunks in Qdrant if the dataset includes semantic questions. Set `GEMINI_API_KEY` in `.env` for the example below. Both modes use the model selected by `GEMINI_MODEL`.

```bash
python -m evaluation.run --provider gemini
```

Use `--dataset` to run a reviewed file and `--limit` for a short smoke test. The runner matches each question's raw run against the processed manifest for the configured data source. Reports and per-question outputs are stored under `$ARTIFACTS_DIR/evaluation/<timestamp>/`.

For Groq, set `GROQ_API_KEY` and `GROQ_MODEL` in `.env`, then pass `--provider groq`.

After the [OpenSSH pipeline example](../data_pipeline/README.md#openssh-example), run a five-question smoke test from the generated file.

```bash
python -m evaluation.run --provider groq --limit 5
```

The runner saves `run.json`, the selected `questions.jsonl`, and the corpus manifest before generation. It appends each answer to `llm_only_results.jsonl` or `rag_results.jsonl` as soon as the response is available. Each row includes the question, expected CVEs and status, model answer, inferred status, and any error. After a clean stop or interruption, `summary.json` reports the target questions, paired rows, scored pairs, and failures per mode.

The comparison scores questions for which both modes completed without a request or retrieval error. An incomplete run has `completed: false` and a nonzero exit code. Use the answer logs to inspect individual failures.

Groq calls are spaced by six seconds by default. Use `--request-interval` to set the minimum interval between LLM attempts and `--max-retries` to change the default of two retries for HTTP 429 and transient server errors. The runner honors a `Retry-After` delay up to one minute and stops on an exhausted rate limit or HTTP 401, 403, or 404. Reported per-question latency excludes deliberate pacing and retry waits. `wall_seconds` includes them.

## Metrics

The report includes exact CVE-set match, status accuracy, combined CVE-and-status accuracy, version status accuracy, CVE precision, recall and F1, citation URL precision and coverage, correct abstention, and latency. Version status accuracy uses the CVE/version checks as its denominator. The CVE-outside-catalog metric uses an optional global NVD snapshot. Refresh it with the following command.

```bash
python -m data_pipeline.cve_catalog --refresh
```

Metrics that require the global snapshot are `null` when it is unavailable. The report includes catalog metadata when its manifest matches the CVE list used in the run. A partial or older catalog can overcount missing IDs. Use a verified complete snapshot for claims about CVE existence.

## OpenSSH pilot results

The pilot ran B0 and B2 on the same 40 draft NVD questions with Groq `openai/gpt-oss-120b`. The chart counts questions that met each criterion.

![OpenSSH pilot chart showing B0 versus B2 across 40 questions and four question types](openssh-pilot-results.png)

| Metric | What it counts | B0 | B2 |
| --- | --- | ---: | ---: |
| Exact CVE set | Questions where the predicted and expected CVE sets are equal | 21/40 | 30/40 |
| Exact CVE set and status | Questions where both the CVE set and the verdict match | 15/40 | 29/40 |
| Version status accuracy | Correct verdicts within the 20 CVE/version checks | 9/20 | 17/20 |
| CVE micro F1 | Harmonic mean of precision and recall, counting each CVE once per question and pooling across questions | 20.3% | 96.8% |

Five inventory questions account for 157 of the 192 expected CVE mentions, so they carry most of the weight in micro F1. The current scorer infers verdicts from text and checks citation URLs against expected URLs. Verifying whether a citation supports the explanation, severity, or remediation requires reviewing the claim and its evidence. The pilot used draft labels and covered B0 and B2.

### Scored examples

| Question from the pilot | Draft answer | What happened |
| --- | --- | --- |
| Is OpenSSH `9.5p1` affected by `CVE-2023-51384`? | `affected` and the named CVE | Both modes named the CVE. B0 said `not_affected`, so it passed the CVE-set check and failed the verdict check. B2 matched both. |
| Which OpenSSH CVEs in the snapshot belong to `CWE-1284`? | `CVE-2026-59997` | B2's top five missed the expected CVE and the answer abstained. The scorer marked the CVE set wrong. |
| Which OpenSSH CVEs in the snapshot belong to `CWE-284`? | `CVE-2023-51384` | B2 named the expected CVE. The verdict parser interpreted uncertainty about the other candidates as an abstention and marked the answer wrong. A manual check of CWE membership counted this case as correct. |
