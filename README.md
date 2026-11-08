# NetVuln RAG

NetVuln RAG answers CVE questions with citations for OpenSSH, OpenVPN Community, and Fortinet FortiOS. The default product catalog queries NVD for the 16 software versions in the proposal.

## Repository layout

| Directory | Purpose |
| --- | --- |
| [`config/`](config/README.md) | Product catalog and runtime settings |
| [`data_pipeline/`](data_pipeline/README.md) | NVD crawl, normalized records, chunks, and Qdrant indexing |
| [`rag/`](rag/README.md) | Question parsing, version checks, retrieval, and cited answers |
| [`api/`](api/README.md) | FastAPI requests and responses |
| [`evaluation/`](evaluation/README.md) | Draft questions, benchmark runs, scoring examples, and the pilot chart |
| `tests/` | Automated tests |
| [`data/`](data/README.md) | Default storage root for source data and processed corpora |
| `artifacts/` | Default storage root for evaluation datasets and results |

## 1. Configure the project

Create a Python 3.11 or newer virtual environment from the repository root. Install dependencies and copy `.env.example` to `.env` on first setup.

Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Linux or macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

Edit [config/products.json](config/products.json) to select products and versions. Set `DATA_DIR` and `ARTIFACTS_DIR` in `.env` to move the storage roots. Relative values are resolved from the repository root. Absolute values can point to mounted server volumes. See the [storage guide](data_pipeline/README.md#storage).

Use `python -m pip install -r requirements-cloud.txt` for a cloud-only checkout. To run the CLI from another directory, install the checkout with `python -m pip install -e .`. The full `requirements.txt` also installs local embedding and test dependencies. [Path and device settings](config/README.md#move-local-data-or-change-compute)

Run `python -m config.check --stage crawl` before preparing data. After preparation, use `--stage index`, `--stage chat`, or `--stage evaluate` to check the corresponding local prerequisites and configuration. [Configuration checks](config/README.md#check-the-resolved-settings)

The example uses Gemini. Fill in `GEMINI_API_KEY` with a key from [Google AI Studio](https://aistudio.google.com/apikey). Change `GEMINI_MODEL` to select a different Gemini model.

```dotenv
LLM_PROVIDER=gemini
GEMINI_API_KEY=your_api_key
GEMINI_MODEL=gemini-3.5-flash-lite
```

To use Groq, set `LLM_PROVIDER=groq`, fill in `GROQ_API_KEY`, and select a model with `GROQ_MODEL`. The example provides `openai/gpt-oss-120b`.

For Qdrant Cloud, set `QDRANT_URL` to the HTTPS cluster endpoint and `QDRANT_API_KEY` to the cluster database key. The example uses Qdrant Cloud Inference with `intfloat/multilingual-e5-small` for both document and query embeddings. Enable Cloud Inference on the cluster if needed.

## 2. Prepare the data

```bash
python -m data_pipeline.prepare --all-products --skip-index
```

This crawls NVD and builds structured records and evidence chunks. Exact CVE lookup and version checks use the processed files. Semantic search also uses a Qdrant collection. Build it after configuring your cluster.

```bash
python -m data_pipeline.index
```

Use a fresh collection for a new corpus or when changing embedding models. The explicit `--recreate` option drops and rebuilds the configured collection. With `EMBEDDING_PROVIDER=qdrant_cloud`, Qdrant generates vectors from the text sent by the app. See the [data pipeline guide](data_pipeline/README.md) for the individual commands and manifest layout.

## 3. Ask a question

```bash
python -m rag.generation.chatbot --text "Which CVEs affect OpenSSH 9.7p1?"
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

The API exposes `GET /health`, `POST /search`, and `POST /chat`. Open `http://127.0.0.1:8000/docs` for the request and response schemas.

## 4. Run the evaluation

```bash
python -m evaluation.build
python -m evaluation.run
```

The builder writes candidate questions to `$ARTIFACTS_DIR/evaluation/questions.jsonl`. Review the questions, expected CVEs, and citations before benchmarking. The current runner compares LLM-only and RAG on the same questions. Index the corpus in Qdrant before evaluating semantic queries. See the [evaluation guide](evaluation/README.md).

## Run the OpenSSH pilot on Kaggle

1. Open a Kaggle Notebook with Internet enabled and use the CPU runtime. Bring in the source from the branch or snapshot you want to test, then install `requirements-cloud.txt` from the repository root. Groq runs generation and Qdrant Cloud Inference runs embeddings. [Kaggle Notebook settings](https://www.kaggle.com/docs/notebooks)
2. Set up the [Kaggle configuration cell](config/README.md#kaggle-notebook) to load credentials from Kaggle Secrets and put data and results under `/kaggle/working`.
3. Follow the [OpenSSH walkthrough](data_pipeline/README.md#openssh-example) for a fresh crawl or attach the saved pilot snapshot and use its matching collection and embedding settings. Keep the question file and processed manifest from the same NVD run.
4. Check the inputs with `python -m config.check --stage evaluate --provider groq`, then run `python -m evaluation.run --provider groq --limit 5`. The benchmark paces Groq calls, retries transient errors, and saves each answer as it arrives. Use [Save & Run All](https://www.kaggle.com/docs/notebooks) to capture the notebook version and outputs under `/kaggle/working`.

Run the offline test suite with `python -m pytest -q`.
