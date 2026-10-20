# NetVuln RAG

Hệ thống RAG cơ bản để tra cứu lỗ hổng cho thiết bị và phần mềm mạng. Core được viết theo schema chung; cấu hình mặc định hiện dùng **NVD + Fortinet FortiOS**, nhưng có thể đổi sản phẩm hoặc thêm nguồn dữ liệu mà không phải sửa retrieval, LLM hay FastAPI.


## 1. Kiến trúc

```text
External source
  -> source adapter
  -> raw data
  -> common vulnerability schema
  -> embedding + vector store
  -> retrieval + version matching
  -> LLM + citations
  -> CLI hoặc FastAPI
```

Các tầng chỉ phụ thuộc vào contract của tầng bên dưới. NVD là một adapter, không phải logic của toàn project.

## 2. Cấu trúc project

```text
netvuln-rag/
├── src/
│   └── main.py                       # FastAPI: /health, /search, /chat
├── llm/
│   ├── client.py                     # Gọi model theo provider
│   ├── chatbot.py                    # Ghép retrieval + LLM, terminal chat
│   └── prompts.json                  # Prompt tách khỏi source code
├── rag_system/
│   ├── config.py                     # Cấu hình chung từ .env
│   ├── models.py                     # Data contracts dùng trong RAG
│   ├── pipeline.py                   # Crawl -> process -> index
│   ├── indexer.py                    # Chunk, embedding, vector store
│   ├── retrieval.py                  # Parse query và retrieve evidence
│   ├── versioning.py                 # So sánh version range
│   └── ingestion/
│       ├── base.py                   # Contract cho source adapter
│       ├── crawler.py                # Lệnh crawl tổng quát
│       ├── processor.py              # Lệnh process tổng quát
│       └── adapters/
│           └── nvd.py                # Chi tiết riêng của NVD
├── tests/
│   └── evaluation/                   # So sánh LLM-only và RAG
└── data/
    ├── raw/<source>/
    └── processed/
```

Tên `nvd.py` được giữ cụ thể có chủ đích: code phụ thuộc NVD phải nằm đúng một chỗ. Những phần còn lại dùng tên và schema tổng quát.

## 3. Cài đặt

Yêu cầu Python 3.11+ và Docker Desktop.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
docker compose up -d qdrant
```

Qdrant dashboard: `http://localhost:6333/dashboard`.

## 4. Chọn nguồn và sản phẩm

Profile mặc định trong `.env.example`:

```env
DATA_SOURCE=nvd
TARGET_VENDOR=fortinet
TARGET_PRODUCT=fortios
TARGET_PRODUCT_ALIASES=fortios,fortinet os
TARGET_CPE=cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*
```

Để đổi sang sản phẩm khác có dữ liệu NVD, thay profile trên và dùng collection mới hoặc chạy lại index với `--recreate`.

## 5. Chuẩn bị dữ liệu

Chạy cả pipeline:

```powershell
python -m rag_system.pipeline
```

Dùng raw data đã có:

```powershell
python -m rag_system.pipeline --skip-crawl
```

Hoặc chạy riêng từng bước:

```powershell
python -m rag_system.ingestion.crawler
python -m rag_system.ingestion.processor
python -m rag_system.indexer
```

Tạo lại collection khi đổi schema hoặc embedding model:

```powershell
python -m rag_system.indexer --recreate
```

## 6. Chọn LLM

Ollama local:

```powershell
docker compose --profile ollama up -d
docker exec netvuln-ollama ollama pull qwen2.5:3b
```

```env
LLM_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:3b
```

Hoặc OpenAI:

```env
LLM_PROVIDER=openai
OPENAI_API_KEY=your-api-key
OPENAI_MODEL=gpt-4.1-mini
```

## 7. Sử dụng

Chat trong terminal:

```powershell
python -m llm.chatbot
```

Gửi một câu rồi thoát:

```powershell
python -m llm.chatbot --text "FortiOS 7.2.5 có bị CVE-2024-21762 ảnh hưởng không?"
```

Chạy API:

```powershell
uvicorn src.main:app --reload --host 127.0.0.1 --port 8000
```

Swagger UI: `http://127.0.0.1:8000/docs`.

Retrieval không gọi LLM:

```http
POST /search
Content-Type: application/json

{"query": "CVE-2024-21762", "top_k": 5}
```

Chat có RAG:

```http
POST /chat
Content-Type: application/json

{
  "question": "Phiên bản 7.2.5 có bị CVE-2024-21762 ảnh hưởng không?",
  "provider": "ollama",
  "top_k": 5
}
```

## 8. Mở rộng project

### Thêm nguồn dữ liệu

1. Tạo adapter mới trong `rag_system/ingestion/adapters/` và implement `SourceAdapter`.
2. Chuyển dữ liệu về schema chung có các field `vulnerability_id`, `vendor`, `product`, `description`, `affected_versions`, `source_url` và `source`.
3. Đăng ký adapter trong `rag_system/ingestion/adapters/__init__.py`.
4. Đặt `DATA_SOURCE` trong `.env`.

Indexer, retriever, chatbot và API không cần sửa.

### Thêm LLM provider

Thêm hàm generate và đăng ký provider trong `llm/client.py`. API nhận provider dạng chuỗi nên không phải thay request schema.

### Đổi vector database hoặc embedding

Interface cần thay nằm trong `rag_system/indexer.py` và `rag_system/retrieval.py`; ingestion, LLM và API không phụ thuộc schema riêng của NVD.

## 9. Evaluation

Sau khi build index và khởi động LLM:

```powershell
python -m tests.evaluation.run_evaluation --provider ollama
```

Kết quả được lưu tại `artifacts/evaluation/<timestamp>/`. Xem [hướng dẫn evaluation](tests/evaluation/README.md).

## 10. Kiểm tra code

Chỉ kiểm tra syntax, không crawl, tải model, gọi vector store hoặc LLM:

```powershell
python -m compileall -q src llm rag_system tests
```

Unit test logic:

```powershell
pytest -q
```

## 11. Giới hạn hiện tại

- Adapter có sẵn mới chỉ là NVD.
- Identifier parser hiện hỗ trợ CVE.
- Dense retrieval, chưa có BM25, hybrid search hoặc reranker.
- Version matcher phù hợp nhất với version số như `7.2.5`.
- “Không tìm thấy” chỉ có nghĩa là không có evidence trong index hiện tại.
