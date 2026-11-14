# NetVuln RAG

NetVuln RAG answers CVE questions with citations for OpenSSH, OpenVPN Community, and Fortinet FortiOS. The current product catalog queries NVD for 16 software versions.

The [AWS experiment deployment](infra/aws/README.md) combines CloudFormation with agentless Ansible to install sixteen fixed software versions, collect real device facts, and check service readiness and network isolation. Workload flows have individual security groups and router firewall rules; sharing a VPC does not grant unrestricted access. All sixteen source builds have been checked locally, and a [live OpenSSH pilot](infra/aws/audit/PILOT.md) has compared LLM and RAG using Ansible facts. AWS deployment, reviewed CVE ground truth and the full benchmark remain pending; the [implementation audit](infra/aws/audit/IMPLEMENTATION.md) records the boundaries. The [revised proposal](proposal/proposal.pdf) plans CVE/advisory collection for five stable releases of eight products plus older test builds, two installed versions per product, and 100 questions; the [question draft](proposal/question-plan.md) still requires review. General RAG inventory integration and Greenbone provisioning are subsequent stages. The earlier [Docker validation report](proposal/validation/REPORT.md) is historical evidence.

## Repository layout

| Directory | Purpose |
| --- | --- |
| [`config/`](config/README.md) | Product catalog and runtime settings |
| [`data_pipeline/`](data_pipeline/README.md) | NVD crawl, normalized records, chunks, and Qdrant indexing |
| [`rag/`](rag/README.md) | Question parsing, version checks, retrieval, and cited answers |
| [`api/`](api/README.md) | FastAPI requests and responses |
| [`evaluation/`](evaluation/README.md) | Draft questions, benchmark runs, scoring examples, and the pilot chart |
| [`infra/`](infra/aws/README.md) | CloudFormation, native installers, Ansible and network policy |
| [`collector/`](collector/facts.py) | One-shot observed facts and immutable inventory snapshots |
| [`proposal/`](proposal/README.md) | Revised proposal, PDF, and functional validation evidence |
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

Use the same `requirements.txt` on laptops, servers, and Kaggle. Choose the service endpoints and embedding device in `.env` or set the equivalent environment variables. To run the CLI from another directory, install the checkout with `python -m pip install -e .`. [Service and device settings](config/README.md#choose-services-and-device)

Run `python -m config.check --stage crawl` before preparing data. After preparation, use `--stage index`, `--stage chat`, or `--stage evaluate` to check the corresponding local prerequisites and configuration. [Configuration checks](config/README.md#check-the-resolved-settings)

The laptop and Kaggle examples use Groq. Fill in `GROQ_API_KEY` and select a model with `GROQ_MODEL`.

```dotenv
LLM_PROVIDER=groq
GROQ_API_KEY=your_api_key
GROQ_MODEL=openai/gpt-oss-120b
```

For Qdrant Cloud, set `QDRANT_URL` to the HTTPS cluster endpoint and `QDRANT_API_KEY` to the cluster database key. The example uses Qdrant Cloud Inference with `intfloat/multilingual-e5-small` for both document and query embeddings. Enable Cloud Inference on the cluster if needed.

## 2. Prepare the data

```bash
python -m data_pipeline.prepare --all-products --skip-index
```

This crawls NVD and writes structured records and evidence chunks to the processed snapshot. Exact CVE lookup and version checks use those files. To enable semantic search, embed the chunks and upsert their vectors and source metadata into the Qdrant collection configured in `.env`.

```bash
python -m data_pipeline.index
```

Use a fresh collection for a new corpus or when changing embedding models. The explicit `--recreate` option drops and rebuilds the configured collection. To change chunking, edit `data_pipeline/chunker.py` and run `python -m data_pipeline.process --rechunk` before indexing. To change only the embedding model, reuse the existing chunks and run `index` with the new model and collection. [Rebuild steps and file layout](data_pipeline/README.md#what-to-rerun)

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

The builder writes candidate questions to `$ARTIFACTS_DIR/evaluation/questions.jsonl`. Review the questions, expected CVEs, and citations before benchmarking. Select one or more benchmark modes with `--modes`. Index the corpus in Qdrant before evaluating RAG semantic queries. [Benchmark modes and their inputs](evaluation/README.md#run-the-benchmark)

System evaluation reports answer quality and LLM efficiency as its main metric groups in `summary.json` and `metrics.csv`. LLM efficiency includes tokens, latency, observed output tokens/second, retries and failures. [Metric definitions](evaluation/README.md#metrics)

Use `python -m evaluation.run --provider groq --limit 5 --stream` to watch live LLM output, followed by the final validated answer. Streaming runs also measure time to first text (TTFT), visible in the saved reports and terminal check.

To compare saved answers in the terminal, run `python -m evaluation.manual_check`. The viewer opens with a whole-run LLM efficiency table (`u` repeats it). Selecting a question shows its LLM metrics, question text, system reference, full B0/B1/B2 answers and sources side by side, plus a CVE matrix with one CVE per row marked present, missing or extra. [Terminal viewer](evaluation/README.md#inspect-saved-answers-in-the-terminal)

## Run individual stages

| Task | Command from the repository root | Read or edit |
| --- | --- | --- |
| Check settings | `python -m config.check --stage crawl` | [Settings](config/settings.py) and [configuration checks](config/check.py) |
| Crawl NVD | `python -m data_pipeline.crawl --all-products` | [Crawler CLI](data_pipeline/crawl.py) and [NVD adapter](data_pipeline/nvd.py) |
| Normalize an existing crawl | `python -m data_pipeline.process --all-products --normalize-only` | [Processing](data_pipeline/process.py) |
| Create chunks from that normalized output | `python -m data_pipeline.process --chunks-only` | [Chunking](data_pipeline/chunker.py) |
| Rebuild chunks from the published structured records | `python -m data_pipeline.process --rechunk` | [Chunking](data_pipeline/chunker.py) |
| Prepare local vectors or Cloud Inference inputs | `python -m data_pipeline.index --stage prepare` | [Index input preparation](data_pipeline/index.py) |
| Push the saved input and metadata to Qdrant | `python -m data_pipeline.index --stage push` | [Qdrant upsert](data_pipeline/index.py) |
| Inspect retrieval or ask a question | `python -m uvicorn api.main:app` | [API](api/README.md), [retriever](rag/retrieval/retriever.py), and [prompts](rag/generation/prompts.json) |
| Build benchmark questions | `python -m evaluation.build` | [Dataset builder](evaluation/build.py) |
| Run a single benchmark mode | `python -m evaluation.run --modes llm_bm25` | [Runner](evaluation/run.py), [baseline evidence selection](evaluation/baselines.py), and [metrics](evaluation/metrics.py) |

Run `python -m data_pipeline.prepare --all-products` from crawl through Qdrant upload. Add `--evaluate` to build questions and benchmark the same snapshot. [Full pipeline commands](data_pipeline/README.md#run-all-stages-in-order)

## Run the OpenSSH pilot on Kaggle

1. Open a Kaggle Notebook with Internet enabled and use the CPU runtime for the Groq and Qdrant Cloud example. Bring in the source from the branch or snapshot you want to test, then run `python -m pip install -r requirements.txt` from the repository root. [Kaggle Notebook settings](https://www.kaggle.com/docs/notebooks)
2. Set up the [Kaggle configuration cell](config/README.md#kaggle-notebook) to load credentials from Kaggle Secrets and put data and results under `/kaggle/working`.
3. Follow the [OpenSSH walkthrough](data_pipeline/README.md#openssh-example) for a fresh crawl or attach the saved pilot snapshot and use its matching collection and embedding settings. Keep the question file and processed manifest from the same NVD run.
4. Check the inputs with `python -m config.check --stage evaluate --provider groq`, then run `python -m evaluation.run --provider groq --limit 5`. The benchmark paces Groq calls, retries transient errors, and saves each answer as it arrives. Use [Save & Run All](https://www.kaggle.com/docs/notebooks) to capture the notebook version and outputs under `/kaggle/working`.

For a fresh run from crawl through benchmark, use `python -m data_pipeline.prepare --all-products --evaluate --eval-limit 5`. This compares the raw and BM25 baselines with RAG. To benchmark a saved snapshot, include its matching `raw/` directory and use the separate evaluation commands. Open `netvuln-results/evaluation/<timestamp>/summary.json` in the Kaggle version's Output tab. [Metric definitions](evaluation/README.md#metrics)

Install the test extra with `python -m pip install -e '.[test]'`, then run the offline test suite with `python -m pytest -q`.
