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

```bash
python -m data_pipeline.process --all-products --run latest
python -m data_pipeline.index
```

Processing deduplicates CVEs within each product and keeps the versions returned by NVD. Each successful run publishes `$DATA_DIR/processed/manifest.json` after writing all selected products to `processed/snapshots/<snapshot-id>/`. The manifest records the input run IDs and relative artifact paths with hashes. Retrieval and indexing use the published scope. Run with `--all-products` for a combined corpus. Earlier snapshot files remain available to in-flight readers and for inspection.

Copy the processed directory with its manifest when moving a corpus between machines. Source references use the configured raw and curated roots. The manifest reader also translates absolute artifact paths from older snapshots to the corresponding portable legacy paths.

With `EMBEDDING_PROVIDER=qdrant_cloud`, indexing and semantic queries send text to Qdrant Cloud Inference. Set the model, dimensions, and any model-specific document and query prefixes in `.env`. The example uses the 384-dimensional multilingual E5 model. Select `EMBEDDING_PROVIDER=local` and a Sentence Transformers model for local embeddings.

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
| Chunk and index | `chunks/openssh/chunks.jsonl` within the manifest's snapshot and Qdrant | The `overview` chunk keeps the CVE ID and its NVD URL. Qdrant stores an embedding and the chunk metadata. |
| Build a draft benchmark | `$ARTIFACTS_DIR/evaluation/questions.jsonl` | A version check asks whether `9.5p1` is affected. Its draft label is `affected` and its expected CVE set contains `CVE-2023-51384`. |

The pilot produced 34 normalized CVEs, 191 indexed chunks, and 222 draft questions. Counts depend on the NVD snapshot.

See the [scored examples](../evaluation/README.md#openssh-pilot-results) for the difference between retrieving a CVE, naming it in an answer, and getting the affected version right.

## Legacy catalog

[config/products.legacy.json](../config/products.legacy.json) contains RouterOS and FortiOS profiles with vendor advisories. Select it through `PRODUCT_CONFIG_FILE` and use separate data roots and a separate Qdrant collection for that corpus. See the [RouterOS advisory curation guide](../data/curated/routeros/README.md).
