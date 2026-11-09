# Data pipeline

The default [product catalog](../config/products.json) defines products, version labels, and full CPE names. The crawler calls NVD CVE API 2.0 with `cpeName` and `isVulnerable` for each configured version, including labels such as `9.7p1`.

## Storage

Set the storage roots in `.env`. Relative values are resolved from the repository root. Absolute values can point to a mounted volume on a server.

```dotenv
DATA_DIR=data
ARTIFACTS_DIR=artifacts
```

`DATA_DIR` contains `raw/`, `processed/`, `curated/`, and `reference/`. When `DATA_DIR` is set, these directories follow that root. Existing configurations can still use individual directory variables when `DATA_DIR` is unset. The evaluation builder and runner share `$ARTIFACTS_DIR/evaluation/`.

## Crawl

```bash
python -m data_pipeline.crawl --all-products
```

Each product run is stored under `$DATA_DIR/raw/<product>/<source>/<run-id>/`. The raw manifest records the source, query CPEs, page filenames, and record counts. Use `--product openssh --limit 2` for a sample of up to two records per CPE. The evaluation builder requires completed queries with all results.

## Process and index

### Normalize the raw data

```bash
python -m data_pipeline.process --all-products --normalize-only
```

This reads the latest completed raw run for each selected product, deduplicates CVEs, and writes `structured/<product>/vulnerabilities.jsonl` under `processed/snapshots/<snapshot-id>/`. `processed/normalized-manifest.json` records the structured file hashes and raw run IDs. Use `--product openssh --run <run-id>` to pin a specific run. The published retrieval snapshot stays active during normalization.

### Create chunks

```bash
python -m data_pipeline.process --chunks-only
```

This reads the normalized manifest, runs [`chunker.py`](chunker.py), and writes `chunks/<product>/chunks.jsonl` into a new snapshot alongside the structured files. It publishes `processed/manifest.json` after all selected products finish. Use `--rechunk` to take structured files from the already published retrieval snapshot instead. The default `process` command combines normalization and chunking.

Copy the processed directory with its manifest when moving a corpus between machines. Source references use the configured raw and curated roots. The manifest reader also translates absolute artifact paths from older snapshots to the corresponding portable legacy paths.

### Prepare index inputs

```bash
python -m data_pipeline.index --stage prepare
```

This reads the published `chunks.jsonl` files and saves `$ARTIFACTS_DIR/index/points.json`. With `EMBEDDING_PROVIDER=local`, the file contains computed vectors. With `EMBEDDING_PROVIDER=qdrant_cloud`, it contains document text and model names. Both contain the point IDs, source metadata, and embedding settings.

### Push to Qdrant

```bash
python -m data_pipeline.index --stage push
```

This reads the saved file and upserts into `QDRANT_COLLECTION` at `QDRANT_URL`. Qdrant Cloud Inference computes vectors during that upsert. Use `--bundle` on both commands to choose a different file or transfer it between machines. Keep the same embedding settings when pushing the file. Run `python -m data_pipeline.index` to prepare and push in one command.

### Run all stages in order

Run from the repository root on a laptop or in a Kaggle notebook shell.

```bash
python -m data_pipeline.prepare --all-products
```

Add `--evaluate` to build questions from the indexed snapshot's pinned raw runs and compare B1-Raw, BM25, and RAG using the LLM configured in `.env`.

```bash
python -m data_pipeline.prepare --all-products --evaluate --eval-limit 5
```

Omit `--eval-limit` to score the entire generated question file. Use `--product openssh` in place of `--all-products` for an OpenSSH run. The individual commands above retain the normalized manifest and prepared index input for later use.

### What to rerun

| Change | Reuse | Run |
| --- | --- | --- |
| Change chunking in [`chunker.py`](chunker.py) | Normalized records and their raw run IDs | `process --rechunk`, then prepare and push |
| Change the embedding model, provider, or prefixes | The published chunks | Update `.env`, then prepare and push |
| Change the Qdrant destination | The prepared index input | Update `QDRANT_URL` or `QDRANT_COLLECTION` and run `index --stage push` |
| Change normalization or version rules | Existing raw crawl | Normalize, create chunks, prepare, and push |

`--rechunk` rebuilds the chunks for the products in the currently published manifest. It copies the structured records into a new snapshot, preserves their raw run IDs, and switches the manifest after all chunks are written. Use a fresh `QDRANT_COLLECTION` before indexing changes to the corpus or embedding configuration. This keeps the previous collection available for comparison. `--recreate` explicitly drops the configured collection before rebuilding it.

Use `python -m data_pipeline.prepare --all-products --skip-index` to crawl and process in one command. Without `--skip-index`, the command creates a new collection. Choose a fresh collection for a new corpus or pass `--recreate-index` to explicitly replace the current one. With the standalone index command, `--recreate` drops the current collection before indexing.

## OpenSSH example

This example follows `CVE-2023-51384` for OpenSSH `9.5p1` through the saved pilot. The catalog supplies the CPE and the NVD request applies `isVulnerable`.

With a fresh data directory and a dedicated Qdrant collection configured, run the same stages for a new OpenSSH snapshot.

```bash
python -m data_pipeline.prepare --product openssh --skip-index
python -m data_pipeline.index
python -m evaluation.build --product openssh
```

| Stage | File or destination | Example from the pilot |
| --- | --- | --- |
| Crawl | `$DATA_DIR/raw/openssh/nvd/<run-id>/page_0001.json` | The `9.5p1` query returned 34 records. One entry has `cve.id = "CVE-2023-51384"`. |
| Process | `structured/openssh/vulnerabilities.jsonl` within the manifest's snapshot | The record has `product_id = "openssh"` and an effective `affected` rule with `exact_versions = ["9.5p1"]`. |
| Create chunks | `chunks/openssh/chunks.jsonl` within the manifest's snapshot | The `overview` chunk keeps the CVE ID and its NVD URL. |
| Embed and upsert | The configured Qdrant collection | Qdrant stores one vector and its metadata for each chunk. |
| Build a draft benchmark | `$ARTIFACTS_DIR/evaluation/questions.jsonl` | A version check asks whether `9.5p1` is affected. Its draft label is `affected` and its expected CVE set contains `CVE-2023-51384`. |

The pilot produced 34 normalized CVEs, 191 indexed chunks, and 222 draft questions. Counts depend on the NVD snapshot.

See the [scored examples](../evaluation/README.md#openssh-pilot-results) for the difference between retrieving a CVE, naming it in an answer, and getting the affected version right.

## Legacy catalog

[config/products.legacy.json](../config/products.legacy.json) contains RouterOS and FortiOS profiles with vendor advisories. Select it through `PRODUCT_CONFIG_FILE` and use separate data roots and a separate Qdrant collection for that corpus. See the [RouterOS advisory curation guide](../data/curated/routeros/README.md).
