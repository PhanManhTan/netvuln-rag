# FastAPI

The API exposes retrieval and answer generation over HTTP. `GET /health` checks the configured Qdrant collection, `POST /search` returns evidence and version decisions, and `POST /chat` generates a cited answer.

## Start the API

Configure the [runtime settings](../config/README.md) and [prepare the OpenSSH corpus](../data_pipeline/README.md#openssh-example).

```bash
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/docs` to try each endpoint.

## Inspect the evidence

Send this request body to `POST /search` in the interactive API docs.

```json
{
  "query": "Is OpenSSH 9.5p1 affected by CVE-2023-51384?"
}
```

Example response excerpt for the pilot snapshot

```json
{
  "version_matches": [
    {
      "product_id": "openssh",
      "vulnerability_id": "CVE-2023-51384",
      "version": "9.5p1",
      "status": "affected"
    }
  ]
}
```

The full response includes the parsed query and evidence chunks under `results`. To generate an answer, send the same text under the `question` key to `POST /chat`. The chat response reports the model's valid source references in `citations` and the CVEs retrieved as evidence in `retrieved_evidence_cves`.

Health checks return HTTP 503 when the corpus or vector store is unavailable. Chat returns HTTP 502 when generation fails upstream.
