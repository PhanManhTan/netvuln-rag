# RouterOS vendor advisory curation

`vendor_advisories.jsonl` contains one JSON object per `RouterOS + CVE` pair. It is reviewed data, not crawler output.

Only official `mikrotik.com`, `help.mikrotik.com`, `blog.mikrotik.com`, or `forum.mikrotik.com` URLs are accepted. A forum row is valid only when the quoted post/reply is from an identifiable MikroTik representative; record that verification in `notes`.

Workflow:

1. Normalize in a first pass: record CVE, direct evidence, provenance, branch-local version rules, and `source_content_hash`; leave `review_status` as `draft`.
2. In a separate pass, reopen the source and verify product, CVE, every boundary, and the content hash. Fill `reviewed_by`/`reviewed_at`, then change the status to `approved`.

Only `approved` rows take precedence over NVD. Draft and rejected rows are still schema-validated but never affect conclusions. “Fixed in X” means exact version X only. A `not_affected` range beginning at X is allowed only when the evidence explicitly says “X or above”.

The milestone gate is at least 15 curated CVEs and at least 10 with explicit affected/fixed rules. Check the counts in `$DATA_DIR/processed/manifest.json` after processing.

Example (keep each object on one line in the JSONL file):

```json
{"schema_version":"1.0","product_id":"routeros","vulnerability_id":"CVE-YYYY-NNNN","advisory_id":"stable-local-id","title":"...","source_url":"https://mikrotik.com/...","source_type":"announcement","published":null,"updated":null,"retrieved_at":"2026-01-01T00:00:00Z","version_rules":[{"source_id":"stable-local-id","authority":"vendor","status":"affected","branch":"7.2","version_start_including":"7.2.0","version_end_including":"7.2.3","evidence_text":"direct short excerpt","priority":1}],"fixed_versions":[],"evidence_text":"direct short excerpt","source_content_hash":"0000000000000000000000000000000000000000000000000000000000000000","review_status":"draft","normalized_by":"name","reviewed_by":null,"reviewed_at":null,"notes":""}
```
