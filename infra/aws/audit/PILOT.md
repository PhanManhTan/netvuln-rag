# Pilot local: OpenSSH → Ansible facts → LLM/RAG

Ngày 2026-11-14 UTC. Đây là một câu chẩn đoán tích hợp, không phải benchmark
100 câu hoặc kết quả Accuracy toàn câu. Không thực hiện khai thác lỗ hổng.

## Bản cài và dữ kiện quan sát

- Codespace Ubuntu 24.04 x86_64; OpenSSH Portable 9.6p1 build native từ archive
  upstream đã khóa, không patch, prefix riêng dưới /tmp/netvuln-openssh-pilot/.
- sshd root chạy riêng trên 127.0.0.1:22222, không thay sshd/cổng 22 của hệ thống.
- Ansible local connection thu được binary/version/hash, PID/UID, cấu hình hiệu
  lực, libc glibc 2.39, địa chỉ/route và 581 package. Đường SSH liên máy của fleet
  chưa chạy AWS; local connection không được báo là đã kiểm tra SSH fan-out.
- LoginGraceTime=120, UsePAM=yes; listener chỉ loopback. Phân loại phần mềm affected
  không đồng nghĩa host có thể bị tấn công từ mạng bên ngoài.
- Source SHA-256: 910211c07255a8c5ad654391b40ee59800710dd8119dd5362de09385aa7a777c.
- Binary SHA-256: 289f299dcfe46676b97b5c63e108c3eef7488036fbac080c8ac66008644b2af5.

Ansible chạy lại có ok=9, changed=1, failed=0: snapshot có timestamp mới là file
thay đổi; cấu hình facts giữ nguyên. Đây không phải bằng chứng toàn bộ installer
16 sản phẩm đã chạy idempotent trên EC2.

## Đáp án tham chiếu và kết quả

Câu hỏi: bản OpenSSH 9.6p1 quan sát được có thuộc phạm vi affected của
CVE-2024-6387 không, xét platform/cấu hình và giới hạn bằng chứng?
Label affected được dựng trước inference từ [CVE chính thức](https://cveawg.mitre.org/api/cve/CVE-2024-6387),
interval 8.5p1–9.7p1 và [release 9.8 upstream](https://www.openssh.org/txt/release-9.8),
đối chiếu source, binary và cấu hình đã quan sát. Hai tài liệu được lưu/hash
trước khi gọi model, không thêm vào KB làm đầu vào RAG trong lượt này.
Label vẫn là draft_source_backed_not_human_approved, cần duyệt độc lập.

Hai chế độ dùng cùng câu hỏi/facts và model Groq openai/gpt-oss-120b. RAG dùng
processed corpus hiện có, không crawl lại hoặc đổi corpus để cải thiện đáp án.

| Lượt chạy | LLM | RAG | Nguồn URL |
| --- | --- | --- | --- |
| Ban đầu, HTTPS demo | CVE/verdict khớp; TP=1 FP=0 FN=0 | CVE/verdict khớp; TP=1 FP=0 FN=0 | LLM 0; RAG 1 URL NVD duy nhất |
| Sau chuyển sang Ansible | CVE/verdict khớp; TP=1 FP=0 FN=0 | CVE/verdict khớp; TP=1 FP=0 FN=0 | LLM 0; RAG 1 URL NVD duy nhất |

Không chọn lượt tốt nhất; giữ cả hai lượt nguyên gốc. Hai source IDs S1/S2 cùng
trỏ một URL NVD, không được tính là hai nguồn độc lập. Whole-answer accuracy
để null và citation correctness vẫn cần kiểm tra nguồn hỗ trợ từng khẳng định.

Các vấn đề thấy khi đọc nguyên câu trả lời:

- Lượt đầu: LLM nêu khoảng affected mở từ 9.0p1 trở lên, khác khoảng chính thức;
  RAG khuyên bản 9.6p2 không có bằng chứng trong context đã truy xuất.
- Lượt Ansible: LLM nói công bố tháng 8/2024; CVE record đã lưu ghi ngày 1/7/2024.
  Cách nói “9.6p1 và các bản trước đó” cũng thiếu cận dưới/ngoại lệ của advisory.
- RAG lượt Ansible kết luận đúng tuple nhưng trả lời thiếu phần giới hạn bằng
  chứng/platform mà câu hỏi yêu cầu. Heuristic không gắn cờ không có nghĩa toàn
  câu đúng; cần bộ chấm claim/điều kiện thay vì chỉ khớp CVE và verdict.

Latency lượt Ansible: LLM khoảng 2.05 giây; RAG 15.40 giây có một retry HTTP 429
và khoảng 14 giây chờ. Request RAG thành công mất khoảng 1.21 giây. Lượt đầu RAG
wall time còn gồm chờ pacing giữa hai mode. Không dùng các số này để kết luận
RAG nhanh/chậm hơn LLM trong benchmark.

## Lưu trữ và tái kiểm tra

Artifact nguyên gốc, được gitignore:

- artifacts/aws/pilot/20261114T175240.310427Z/ — HTTPS demo ban đầu.
- artifacts/aws/pilot/ansible-20261114/ — snapshot Ansible, expected, source hashes,
  câu hỏi, câu trả lời, request attempts, retrieved context và diagnostics.
- artifacts/aws/ansible-pilot/ và ansible-pilot-run.log — facts/playbook local.

[pilot-results.json](pilot-results.json) xuất metadata/chỉ số không chứa credentials.
Chạy lại facts và pilot bằng lệnh trong [README](../README.md). Để chỉ audit kết
quả đã có, dùng python -m evaluation.pilot --audit-only <thư-mục-lượt-chạy>.
Audit giữ nguyên raw answers và từ chối tái dựng context nếu hash manifest KB đổi.
HTTPS demo chỉ được giữ để tái lập lượt cũ; luồng mặc định là facts qua Ansible.

Mốc tiếp theo là gold bao phủ 16 bản cài với CVE/điều kiện/phạm vi rõ ràng,
tách nguồn tạo label khỏi đầu ra model/scanner và chỉ duyệt thủ công các trường
hợp mơ hồ hoặc mâu thuẫn. Một ca CVE phổ biến không ước lượng được chất lượng
mô hình trên toàn bộ proposal.
