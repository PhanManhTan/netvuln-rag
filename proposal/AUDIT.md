# Phạm vi và cách đánh giá hiện tại

Tên đề tài: **RAG tra cứu lỗ hổng cho thiết bị mạng có trích dẫn**. Giữ tiêu đề và sơ đồ đơn giản người dùng đã chỉnh.

| Nội dung | Thiết kế đã chốt |
| --- | --- |
| Phạm vi crawl? | 8 phần mềm × 5 stable releases mới nhất = 40 tổ hợp; bổ sung advisory cho test versions cũ nếu cần. |
| Phạm vi thực nghiệm? | 8 phần mềm × 2 test versions = 16 instance cố định; thêm HAProxy 2.8.0/2.8.9 và dnsmasq 2.86/2.90. |
| Collector cần gì? | Device, software, version; chỉ thêm configuration khi advisory cần để xác định CVE áp dụng. |
| Phần mềm nằm ở đâu trong sơ đồ? | FRR trên router Linux; nginx/Apache trên Web Server; BIND trên DNS Server; OpenVPN trên VPN Server/Client; OpenSSH cung cấp quản trị SSH. |
| Switch được chấm thế nào? | Switch minh họa kết nối mạng; chưa chọn hệ điều hành/firmware switch vào danh sách CVE. |
| Hạ tầng? | VM AWS cùng VPC, bố trí theo vai trò; MGMT chạy RAG/collector. Các instance có ID/IP/cổng riêng, có thể dùng VM/container. |
| Trạng thái thực nghiệm? | Hai bản chạy song song, dựng một lần và giữ nguyên cấu hình; không có bước nâng cấp giữa các lượt. |
| Đầu vào LLM/RAG? | Cùng câu hỏi người dùng, cùng snapshot collector, model/tham số và yêu cầu trích dẫn; RAG chỉ lấy từ knowledge base đã xây, không bổ sung nguồn ngoài lúc trả lời. |
| Đầu vào Greenbone? | Tập thiết bị/IP và quyền truy cập của lab; quét rồi trả CVE theo thiết bị, báo cáo chuẩn hóa và lọc theo phạm vi câu hỏi. |
| Knowledge base? | Xây từ NVD/advisory trước khi dùng; chốt kho/feed khi chấm. |
| Bộ câu hỏi? | 100 câu bao phủ device, software/version, CVE, nhiều device và source evidence. Có question-plan.md gồm 100 câu dự thảo; điền CVE placeholders và duyệt expected answers trước khi chấm. |
| Đáp án chuẩn? | Bản cài/cấu hình và advisory, được thành viên khác duyệt trước khi chấm; lưu riêng, không lấy đầu ra ba phương án làm đáp án. |
| Tách câu trả lời thế nào? | Theo thiết bị, trong mỗi thiết bị theo phần mềm/phiên bản, rồi theo tập CVE. Greenbone được chuẩn hóa tương tự. |
| Khóa chấm phát hiện? | (thiết bị, phần mềm, phiên bản, CVE); loại trùng trong từng câu hỏi, chấm đúng phạm vi câu hỏi. |
| Chỉ số LLM/RAG? | Accuracy toàn câu, độ đúng trích dẫn và tỷ lệ bịa CVE. |
| Chỉ số chung? | Precision/Recall, số báo nhầm/bỏ sót trên các mục đã chuẩn hóa. |
| Thời gian? | Báo riêng collector, mỗi câu LLM/RAG và lượt quét Greenbone. |
| Bố cục? | Giữ năm mục cũ; bảng chỉ số ghi trực tiếp phương án áp dụng, không dùng chú giải dấu kiểm. |
| Thuật ngữ? | Bảng dữ liệu dùng Software, Thành phần triển khai và Test versions, chỉ rõ phần mềm cài trên Router, DNS Server, Web Server hoặc Client. Giữ các thuật ngữ Test set, configuration, Citation correctness, CVE hallucination rate và Latency. |

Chỉ số ghi ngắn: Accuracy, độ đúng trích dẫn, tỷ lệ bịa CVE, Precision/Recall, TP/FP/FN và thời gian. Trích dẫn chấm theo nội dung nguồn; CVE vắng trong corpus chưa đủ để coi là bịa.

Định danh phần mềm/IP được chuẩn hóa để so sánh; không dùng đáp án chuẩn để bổ sung CVE cho kết quả. Lưu đầu ra gốc và kết quả sau chuẩn hóa. Lỗi ánh xạ/ca chưa hỗ trợ ghi riêng; CVE thực sự ảnh hưởng nhưng chưa phát hiện vẫn là bỏ sót.

RAG vẫn báo chưa đủ bằng chứng khi nguồn hoặc thông tin máy chưa đủ; bộ thực nghiệm hiện tại tập trung vào các câu hỏi trên cấu hình mạng cố định.

[Validation](validation/REPORT.md) chỉ xác minh Docker/SSH/collector sơ bộ. Chưa có AWS, các bản cài đối chứng trong bảng, benchmark CVE hoặc Greenbone. Lần này chỉ sửa tài liệu và biên dịch PDF; không sửa runtime hoặc log validation.
