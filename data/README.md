# Data directories

Paths are relative to `DATA_DIR`, which defaults to this directory.

| Path | Contents |
| --- | --- |
| `raw/<product>/<source>/<run-id>/` | Original crawl pages and a run manifest |
| `processed/snapshots/<snapshot-id>/structured/` | Normalized CVE records by product |
| `processed/snapshots/<snapshot-id>/chunks/` | Evidence chunks for retrieval and indexing |
| `processed/manifest.json` | Published snapshot with input run IDs, relative artifact paths, and hashes |
| `reference/nvd/` | Optional global NVD CVE catalog |
| `curated/` | Reviewed vendor advisories for profiles that use them |

Copy the manifest with its referenced files when moving a snapshot between machines. Older snapshots using `processed/structured/` and `processed/chunks/` remain readable. See the [data pipeline guide](../data_pipeline/README.md) for rebuild commands. Generated evaluation datasets are stored under `$ARTIFACTS_DIR/evaluation/`.

