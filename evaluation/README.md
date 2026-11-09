# Evaluation

The benchmark uses the same model and questions across the selected modes. With the default catalog, the builder generates draft questions and expected answers from the raw NVD snapshot.

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

Use `--from-processed` to build questions from the product scope and raw run IDs of the published processed snapshot. The `data_pipeline.prepare --evaluate` command uses this option before running the benchmark.

Check the expected CVEs, affected conditions, and citations against the original records. For natural-language descriptions, rewrite candidate CWE questions and verify the full set of matching CVEs. Select and freeze the reviewed dataset before benchmarking. See [questions.sample.jsonl](questions.sample.jsonl) for the JSONL format.

## Run the benchmark

Use `--modes` to run one or more modes. Each mode requires an LLM and a question file. The table lists the additional inputs and the matching result key in `summary.json`.

| Mode | Evidence | Additional inputs | Summary key |
| --- | --- | --- | --- |
| `llm_only` (B0) | The question alone | None | `baseline` |
| `llm_document` (B1) | Fixed processed evidence per product | Processed manifest and chunks | `document` |
| `llm_raw` (B1-Raw) | Fixed whole NVD JSON records per product | Raw run pinned by `raw_run_id` or by the processed manifest in a joint run | `raw` |
| `llm_bm25` | Top-k processed chunks ranked by BM25 | Processed manifest and chunks | `bm25` |
| `rag` (B2) | Structured version checks or hybrid retrieval | Processed manifest, records, chunks, and a Qdrant index for semantic questions | `rag` |

B1-Raw sorts unique CVEs by ID and uses the same records for every question about that product. The context preserves each included JSON record intact. BM25 resolves the product with the same parser as RAG, then ranks chunks by term matches in one pass. Both baselines use the shared evidence prompt and answer checks.

Set `LLM_PROVIDER` in `.env` or pass `--provider`. The default command runs B0 and B2. `--with-documents` selects B0, B1, and B2.

```bash
python -m evaluation.run
```

Use `--dataset` to run a reviewed file and `--limit` for a short smoke test. The runner matches each question's raw run against the processed manifest for the configured data source. Reports and per-question outputs are stored under `$ARTIFACTS_DIR/evaluation/<timestamp>/`.

For Groq, set `GROQ_API_KEY` and `GROQ_MODEL` in `.env`, then pass `--provider groq`.

After the [OpenSSH pipeline example](../data_pipeline/README.md#openssh-example), run a five-question smoke test from the generated file.

```bash
python -m evaluation.run --provider groq --limit 5
```

Try the raw and BM25 baselines together with RAG, or pass a single mode such as `--modes llm_bm25` to run it independently. Comparisons with a context baseline use a shared 6,000-character evidence limit by default. Use `--context-max-chars` to change it for the run. Whole blocks that exceed the full budget are skipped. RAG applies the limit after retrieval, including for version inventories. `run.json` records the enabled modes, selection rules, raw run IDs, and context limit.

```bash
python -m evaluation.run --modes llm_raw llm_bm25 rag --limit 5
```

The runner saves `run.json`, the selected `questions.jsonl`, and the processed corpus manifest when used. It appends each answer to `<mode>_results.jsonl` as soon as the response is available. Each row includes the question, expected CVEs and status, model answer, inferred status, and any error. After a clean stop or interruption, `summary.json` reports the target questions, rows available for all modes, scored questions, and failures per mode.

The comparison scores questions for which all enabled modes completed without a request or retrieval error. Each pair of modes gets a score difference such as `rag_minus_bm25`. An incomplete run has `completed: false` and a nonzero exit code. Use the answer logs to inspect individual failures.

Groq calls are spaced by six seconds by default. Use `--request-interval` to set the minimum interval between LLM attempts and `--max-retries` to change the default of two retries for HTTP 429 and transient server errors. The runner honors a `Retry-After` delay up to one minute and stops on an exhausted rate limit or HTTP 401, 403, or 404. Reported per-question latency excludes deliberate pacing and retry waits. `wall_seconds` includes them.

## Metrics

`summary.json` reports `llm_usage` per mode for all attempted questions. It includes input, output, and total tokens, plus reasoning and cached input tokens when the provider reports them. Output counts include reasoning where the provider includes it or reports it separately. `reported_attempts` gives the denominator for each token total. A missing provider count is `null` when no attempt reports that field. Modes that made zero calls used zero tokens.

Each answer row includes `llm_requests` with token counts, duration, and success for each generation attempt. The summary counts retries and calls whose responses were filtered after generation. `average_request_latency_seconds` measures the generation request, including network time and excluding retrieval and pacing. `questions_with_llm_call` shows how often each mode called the model.

`evidence_cve_recall` measures the fraction of expected CVE mentions present in the selected evidence. Compare it with answer `cve_recall` to see whether a missing CVE was available to the model. It is `null` for B0 and for slices without expected CVEs.

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
