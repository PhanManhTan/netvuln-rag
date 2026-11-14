# Kết quả kiểm tra lab và collector

Chạy ngày 10/11/2026 (UTC). Phạm vi: kiểm tra tích hợp mạng Docker và dữ liệu thu qua SSH, **chưa phải benchmark RAG hoặc xác nhận khai thác CVE**. Kết quả chi tiết và lệnh đã chạy nằm trong [summary.json](summary.json).

| Kiểm tra | Kết quả | Bằng chứng |
| --- | --- | --- |
| Compose hợp lệ | PASS | `docker compose ... config --quiet` trả 0 |
| Ba nút khởi động | PASS | R1, H1 và C1 healthy |
| Đường đi qua router và SSH qua mạng dữ liệu | PASS | C1 → 172.30.10.254 (R1) → 172.30.20.20 (H1); ping và SSH thành công |
| Thu thập ba thiết bị bằng SSH | PASS | [baseline.jsonl](baseline.jsonl): ba bản ghi `collection_status: collected` |
| Phân biệt cài đặt và đang chạy | PASS | OpenSSH đang chạy; OpenVPN cài trên R1/C1 nhưng `running: false` |
| Nhận biết cấu hình đổi trên C1 | PASS | `VerifyHostKeyDNS` false → true trong [config-enabled.jsonl](config-enabled.jsonl); R1/H1 không đổi |
| Nhận biết cấu hình đã khôi phục | PASS | C1 trở về false trong [config-restored.jsonl](config-restored.jsonl) |
| Router là thành phần cần thiết của đường dữ liệu | PASS | Dừng R1: ping C1 → H1 thất bại |
| Thiết bị không truy cập được | PASS | [router-unavailable.jsonl](router-unavailable.jsonl): R1 error, H1/C1 vẫn collected; collector trả exit code 1 |
| Khôi phục đường đi | PASS | Bật lại R1: route, ping, traceroute và SSH đạt lại |
| Dừng hạ tầng sau kiểm tra | PASS | Các container lab đã được dừng; giữ image và volume key |

Có 11 kiểm tra chức năng đạt. **Con số này không phải Answer Accuracy của RAG, Citation Precision hay Hallucination Rate.**

## Dữ liệu thực tế đã đọc

- OpenSSH Server: package `1:9.2p1-2+deb12u10`, binary `OpenSSH_9.2`, tiến trình đang chạy.
- OpenVPN trên R1/C1: package `2.6.14-0+deb12u2`, binary `OpenVPN 2.6.14`, chưa chạy tiến trình VPN.
- OS, route IPv4, IP forwarding và một số tùy chọn SSH hiệu lực.
- Cấu hình SSH client chỉ đại diện cho user root và đích `172.30.20.20`.
- Kiểm tra bổ sung trực tiếp trên C1 xác nhận package `openssh-client` là `1:9.2p1-2+deb12u10`; collector hiện mới liệt kê package server trong danh sách software và đọc cấu hình client riêng.

Các phiên bản đến từ thiết bị, không lấy từ tên image để gán kết quả. JSON giữ nguyên trường giới hạn và lỗi thu thập; không chứa private key. Mỗi file snapshot tương ứng một trạng thái của cùng lab.

## Đối chiếu nguồn thủ công

Debian Security Tracker liệt kê package OpenSSH `1:9.2p1-2+deb12u10` đã sửa CVE-2025-26465. Vì vậy bật VerifyHostKeyDNS trong lần kiểm tra này **không chứng minh package đang có CVE đó**. Đây là đối chiếu thủ công để minh họa nhu cầu xét backport, chưa phải đầu ra tự động của RAG. [Nguồn Debian](https://security-tracker.debian.org/tracker/CVE-2025-26465)

## Chưa được kiểm tra hoặc chưa triển khai

- Chưa có HTTP endpoint thu thập/nhập snapshot vào RAG.
- Chưa có luồng tự động snapshot → truy xuất advisory → kết luận CVE theo thiết bị.
- Chưa dựng đủ ma trận build có lỗi/đã sửa trong proposal.
- Chưa chạy VPN tunnel/chứng chỉ hoặc thu thập cấu hình VPN hiệu lực.
- Chưa chạy B0–B3 trên bộ gold đã duyệt, chưa có số liệu accuracy/trích dẫn/bịa CVE.
- Chưa tái hiện exploit; không kết luận mạng đã được kiểm toán bảo mật đầy đủ.

## Trạng thái lưu trữ

Đây là bằng chứng lịch sử của lần kiểm tra ngày 10/11/2026. Thư mục lab và các
lệnh Compose ghi trong summary.json không thuộc triển khai hiện tại, nên báo cáo
này không cung cấp lệnh chạy lại từ checkout hiện nay. Giữ nguyên các snapshot
và summary để truy vết lần kiểm tra cũ.

Triển khai hiện tại dùng CloudFormation và Ansible cài native; xem
[hướng dẫn](../../infra/aws/README.md) và [audit](../../infra/aws/audit/IMPLEMENTATION.md).

Các file evidence không chứa gold label, không phải ground truth CVE và không thay thế bộ câu hỏi được duyệt.
