# Configuration

The product catalog defines what to crawl. Runtime settings define where to store files and which services to call. [`products.json`](products.json) contains the proposal's OpenSSH, OpenVPN Community, and FortiOS profiles. [`.env.example`](../.env.example) lists the supported runtime variables.

## Choose services and device

Install `requirements.txt` in either environment. Set these options in `.env` on a laptop or as environment variables in a notebook.

| Setting | Local service or device | Remote service |
| --- | --- | --- |
| `LLM_PROVIDER` | `ollama` with `OLLAMA_URL` and `OLLAMA_MODEL` | `groq`, `gemini`, or `openai` with the provider's key and model |
| `QDRANT_URL` | `http://localhost:6333` with a running Qdrant server | Cluster HTTPS URL with `QDRANT_API_KEY` |
| `EMBEDDING_PROVIDER` | `local` to run Sentence Transformers in Python | `qdrant_cloud` to use Qdrant Cloud Inference |
| `EMBEDDING_DEVICE` | `auto` to choose an available device, `cpu` to force CPU, or `cuda:0` to select the first GPU | Qdrant Cloud Inference selects its own device |

Embedding computation and vector storage are independent. Local embeddings can be written to either a local or remote Qdrant server. Both embedding providers use the configured document and query prefixes. Rebuild the index after changing the model, provider, or prefixes, including when reusing a local index built before local embeddings applied prefixes. Ollama manages the generation device on its own server.

## Use an OpenSSH cloud profile

Copy `.env.example` to `.env` on first setup. Keep its Qdrant Cloud embedding model, dimensions, and prefixes together. Fill in `QDRANT_URL`, `QDRANT_API_KEY`, and `GROQ_API_KEY` for your environment, then set the following values for a separate OpenSSH run.

```dotenv
DEFAULT_PRODUCT_ID=openssh
DATA_DIR=artifacts/evaluation/openssh-demo/data
ARTIFACTS_DIR=artifacts/evaluation/openssh-demo
LLM_PROVIDER=groq
QDRANT_COLLECTION=netvuln_openssh_demo
```

Relative paths resolve from the repository root in a checkout or editable install. After installing a wheel, they resolve from the working directory where you start the app. The default catalog is bundled in either case. Use absolute paths to place data and reports on a server volume or in Kaggle's working directory.

## Move local data or change compute

| Setting | Default behavior | Example override |
| --- | --- | --- |
| `DATA_DIR` | Keep raw, processed, curated, and reference data under `data/` | `/mnt/netvuln/data` |
| `ARTIFACTS_DIR` | Keep evaluation inputs and results under `artifacts/` | `/mnt/netvuln/results` |
| `EMBEDDING_CACHE_DIR` | Use the model library's default cache | `/mnt/netvuln/model-cache` |
| `EMBEDDING_BATCH_SIZE` | Use batches of 32 during indexing | `8` for a machine with less memory |

To use the same local embedding model on a different device, keep `EMBEDDING_MODEL` and the Qdrant collection settings the same. A model change requires re-embedding the corpus. With Qdrant Cloud Inference, the service handles embedding compute.

## Check the resolved settings

Run the check for the stage you plan to start. It shows the configured paths and reports missing prerequisites by name.

```bash
python -m config.check --stage crawl
python -m config.check --stage index
python -m config.check --stage chat
python -m config.check --stage evaluate
```

For evaluation, pass `--dataset`, `--output-dir`, or `--provider` to mirror overrides you plan to pass to the benchmark. Example output from the crawl check

```text
[OK] Product catalog: openssh, openvpn, fortios (…/config/products.json)
[OK] Source: nvd
[OK] Raw output: …/raw
[OK] Processed output: …/processed
```

The check exits with status 1 if a prerequisite fails. It checks local files, the selected device, URL syntax, and whether required credential variables are set. Service reachability and model availability are verified when the corresponding stage runs.

## Kaggle Notebook

Add `GROQ_API_KEY`, `QDRANT_URL`, and `QDRANT_API_KEY` to Kaggle Secrets and enable them for the notebook. Run this cell from the repository root after installing dependencies. [Kaggle User Secrets](https://www.kaggle.com/discussions/product-feedback/114053)

```python
import os

from dotenv import load_dotenv
from kaggle_secrets import UserSecretsClient

load_dotenv(".env.example")
secrets = UserSecretsClient()
for name in ("GROQ_API_KEY", "QDRANT_URL", "QDRANT_API_KEY"):
    os.environ[name] = secrets.get_secret(name)

os.environ.update(
    DEFAULT_PRODUCT_ID="openssh",
    LLM_PROVIDER="groq",
    QDRANT_COLLECTION="netvuln_kaggle_openssh",
    DATA_DIR="/kaggle/working/netvuln-data",
    ARTIFACTS_DIR="/kaggle/working/netvuln-results",
)
```

This example uses a dedicated collection for the [fresh OpenSSH run](../data_pipeline/README.md#openssh-example).
