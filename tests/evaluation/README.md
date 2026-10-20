# Evaluation: LLM-only vs RAG

Thư mục này chạy cùng một model theo hai chế độ:

1. `llm_only`: model trả lời trực tiếp, không retrieval và không context.
2. `rag`: câu hỏi đi qua `RAGChatbot`, vector store, version matcher và citation guard.

## Chuẩn bị

Phải hoàn thành crawl, process và build index trước khi chạy. Qdrant và LLM provider cũng phải hoạt động.

Bộ `questions.jsonl` đi kèm chỉ là ví dụ kiểm tra pipeline. Trước khi dùng trong báo cáo, cần tự xây ít nhất 50–100 câu và kiểm chứng lại gold label từ NVD/advisory hiện hành.

Schema mỗi câu hỏi:

```json
{
  "id": "fortios-cve-001",
  "question": "FortiOS 7.2.5 có bị CVE-2024-21762 ảnh hưởng không?",
  "expected_cves": ["CVE-2024-21762"],
  "expected_status": "affected",
  "notes": "Nguồn dùng để tạo gold label"
}
```

`expected_status` nhận `affected`, `not_affected` hoặc `insufficient_evidence`.

## Chạy evaluation

Ollama:

```powershell
python -m tests.evaluation.run_evaluation --provider ollama
```

OpenAI:

```powershell
python -m tests.evaluation.run_evaluation --provider openai
```

Chạy thử một số câu:

```powershell
python -m tests.evaluation.run_evaluation --provider ollama --limit 3
```

Kết quả được ghi vào `artifacts/evaluation/<timestamp>/`:

- `llm_only_results.jsonl`: câu trả lời baseline.
- `rag_results.jsonl`: câu trả lời có RAG.
- `summary.json`: metrics và độ chênh RAG trừ baseline.

## Metrics

- `cve_exact_match_accuracy`: tập CVE trong câu trả lời khớp hoàn toàn gold set.
- `status_accuracy`: kết luận affected/not affected/insufficient khớp gold label.
- `cve_precision`, `cve_recall`, `cve_f1`: chất lượng mã CVE được trả về.
- `hallucinated_cve_rate`: tỷ lệ CVE không tồn tại trong processed dataset nhưng vẫn được câu trả lời khẳng định.
- `citation_answer_rate`: tỷ lệ câu trả lời có citation.
- `average_latency_seconds`: thời gian trung bình mỗi câu.

Status của LLM-only được suy ra bằng từ khóa nên cần audit thủ công các câu sai hoặc mơ hồ. Đối với báo cáo chính thức, nên có hai người kiểm tra độc lập gold label và citation correctness.

