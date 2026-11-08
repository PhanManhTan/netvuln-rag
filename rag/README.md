# Retrieval and answer generation

The retriever parses the product, version, and CVE ID from a question. Exact CVE and version questions use the processed records and version rules. Semantic questions combine BM25 with Qdrant results. The chatbot sends the evidence to the configured LLM and returns an answer with source URLs.

## Ask an OpenSSH question

Prepare the [OpenSSH corpus](../data_pipeline/README.md#openssh-example) and select an LLM in the [runtime configuration](../config/README.md). Run the following from the repository root.

```bash
python -m rag.generation.chatbot --provider groq --text "Is OpenSSH 9.5p1 affected by CVE-2023-51384?"
```

The CLI prints the answer and its sources. The following abbreviated output uses the corresponding version check from the OpenSSH pilot. The wording can vary between runs.

```text
Bot [answered]:
Có, OpenSSH 9.5p1 bị ảnh hưởng bởi CVE-2023-51384 theo NVD.

Nguồn kiểm chứng:
[S1] https://nvd.nist.gov/vuln/detail/CVE-2023-51384
```

Use [`POST /search`](../api/README.md#inspect-the-evidence) to inspect the version decision and evidence before invoking the LLM.
