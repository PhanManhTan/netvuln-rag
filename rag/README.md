# Retrieval and answer generation

The retriever parses the product, version, and CVE ID from a question. Exact CVE and version questions use the processed records and version rules. Semantic questions combine BM25 with Qdrant results. The chatbot sends the evidence to the configured LLM and returns an answer with source URLs.

Generation requests a JSON envelope with a separate `verdict`, `answer`, and `asserted_cves`. The API and CLI display the explanation as text; evaluation uses the explicit verdict rather than scanning recommendations for phrases such as “not affected.” Saved responses retain the raw model output and identify structured versus legacy text. Malformed JSON is an output error. Filtered CVEs/citations and conclusions that contradict a structured version decision remain available in the audit fields and do not count as correct abstentions.

`asserted_cves` contains CVEs identified or adjudicated in the answer, including explicit `not_affected` decisions. It excludes identifiers merely repeated as unconfirmed questions. A partial answer can retain assertions while its overall verdict is `insufficient_evidence`. For inventory and description tasks, the current evaluation convention uses `affected` to mean the requested CVE information was supplied; deployment applicability must be checked separately.

NVD exact-CPE query membership describes the saved NVD snapshot. It does not establish that every deployment of that version meets the CVE's platform or configuration conditions. When normalizing broad CPE records, unsupported logical or platform conditions are retained as limitations and do not become unconditional version rules. Existing processed snapshots need to be normalized and chunked again to include these safeguards; rebuild their matching vector index before serving the new snapshot.

## Ask an OpenSSH question

Prepare the [OpenSSH corpus](../data_pipeline/README.md#openssh-example) and select an LLM in the [runtime configuration](../config/README.md). Run the following from the repository root.

```bash
python -m rag.generation.chatbot --provider groq --text "Is OpenSSH 9.5p1 affected by CVE-2023-51384?"
```

The CLI prints the answer and its sources.

Add `--stream` to display the model's raw draft as it arrives, then the final checked answer and sources. It works with each supported provider. The draft may include the structured JSON envelope; the final answer still undergoes CVE, citation and verdict checks.

```bash
python -m rag.generation.chatbot --provider groq --stream --text "Is OpenSSH 9.5p1 affected by CVE-2023-51384?"
```

The following abbreviated final answer uses the corresponding version check from the OpenSSH pilot. The wording can vary between runs.

```text
Bot [answered]:
Có, OpenSSH 9.5p1 bị ảnh hưởng bởi CVE-2023-51384 theo NVD.

Nguồn kiểm chứng:
[S1] https://nvd.nist.gov/vuln/detail/CVE-2023-51384
```

Use [`POST /search`](../api/README.md#inspect-the-evidence) to inspect the version decision and evidence before invoking the LLM.
