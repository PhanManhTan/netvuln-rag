# Proposal hiện tại

**RAG tra cứu lỗ hổng cho thiết bị mạng có trích dẫn**: hỏi về phần mềm trên thiết bị trong mạng đã đăng ký; collector đọc thông tin máy, RAG truy xuất CVE/advisory để trả lời có nguồn.

- [PDF — 2 trang](proposal.pdf)
- [Nguồn LaTeX](proposal.tex)
- [Các điểm đã làm rõ](AUDIT.md)
- [Kế hoạch CloudFormation, collector và thực nghiệm tự động](implementation-plan.md)
- [100 câu hỏi dự thảo](question-plan.md)
- [Audit triển khai hiện tại](../infra/aws/audit/IMPLEMENTATION.md)
- [Kiểm tra Docker/collector trước đây](validation/REPORT.md)

## Phạm vi crawl và thực nghiệm

**Crawl:** lấy CVE/advisory cho 5 stable releases mới nhất của mỗi phần mềm tại mốc thu thập: 8 phần mềm × 5 = 40 tổ hợp. Lưu version và source URL. Nếu test version nằm ngoài nhóm này, bổ sung advisory cho bản đó.

**Test setup:** mỗi phần mềm có hai test versions cố định, chạy trên hai instance độc lập (VM/container), tổng 16 tổ hợp.

| Software | Thành phần triển khai | Test versions |
| --- | --- | --- |
| FRRouting | Router (Linux VM) | 8.5.2; 9.0.1 |
| nginx | Web Server, web/reverse proxy | 1.24.0; 1.26.2 |
| Apache HTTP Server | Web Server, HTTP | 2.4.49; 2.4.50 |
| BIND 9 | DNS Server, phân giải tên | 9.18.19; 9.18.24 |
| OpenVPN | VPN Server và Client | 2.6.8; 2.6.10 |
| OpenSSH Portable | Router, Server và Client (SSH) | 9.6p1; 9.7p1 |
| HAProxy | Load Balancer / Reverse Proxy | 2.8.0; 2.8.9 |
| dnsmasq | DNS Server hoặc Router Linux | 2.86; 2.90 |

Collector lấy device, software và version; chỉ thêm configuration khi advisory yêu cầu để quyết định CVE có áp dụng hay không. Các instance giữ cố định trong suốt đánh giá.

AWS gồm các VM cùng VPC, bố trí theo vai trò; MGMT chạy RAG/collector. FRR chạy trên router Linux của lab. Switch trong hình minh họa kết nối mạng, không phải sản phẩm phần mềm được chọn để chấm CVE. Sơ đồ giữ các nhãn vai trò, không gắn tên sản phẩm.

## Dữ liệu và ba phương án

1. Xây knowledge base từ NVD/advisory bằng chuẩn hóa và lập chỉ mục trước khi sử dụng.
2. Dựng lab cố định; collector đọc software/version trên các thiết bị.
3. Test set gồm 100 câu tự viết về device, software/version, CVE, nhiều thiết bị và source evidence. Mỗi câu có expected CVEs/kết luận và source URL, được thành viên khác duyệt theo bản cài/advisory, lưu riêng khỏi knowledge base.
4. LLM và RAG nhận **đúng cùng câu hỏi người dùng + thông tin mạng từ collector**, cùng model/tham số và yêu cầu trích dẫn. RAG chỉ truy xuất knowledge base đã xây; không lấy thêm tài liệu ngoài khi trả lời.
5. Greenbone/OpenVAS nhận tập thiết bị/IP và quyền truy cập rồi trả CVE theo thiết bị. Cả ba phương án được đánh giá trên cùng một hệ thống mạng tại cùng thời điểm.

| Nhóm câu hỏi | Ví dụ | Phạm vi đối chiếu |
| --- | --- | --- |
| Theo thiết bị | Thiết bị A có phần mềm nào liên quan CVE đã công bố? | Các phần mềm/phiên bản và CVE trên A. |
| Theo phần mềm | Phần mềm X trong mạng có CVE nào, nằm trên thiết bị nào? | Các thiết bị chạy X và CVE phù hợp từng phiên bản. |
| Theo CVE | CVE X ảnh hưởng đến thiết bị và phần mềm nào trong mạng? | Tập thiết bị/phần mềm ảnh hưởng, gồm cả đáp án rỗng. |

## Đưa kết quả về cùng đơn vị để so sánh

Tách kết quả theo **thiết bị → phần mềm/phiên bản → tập CVE**. Greenbone được ánh xạ IP/cổng về instance và tên phần mềm về cùng định danh sản phẩm.

Mỗi mục CVE dùng khóa **(thiết bị, phần mềm, phiên bản, CVE)**. Loại trùng theo khóa trong từng câu hỏi rồi so với đáp án trong phạm vi câu hỏi. Giữ đầu ra gốc và kết quả chuẩn hóa để kiểm tra lại; không lấy kết quả của ba phương án làm đáp án chuẩn. Ca không ánh xạ được sản phẩm hoặc chưa có bài kiểm tra phải được báo riêng.

- **LLM/RAG:** Accuracy toàn câu, độ đúng trích dẫn và tỷ lệ bịa mã CVE.
- **Cả ba:** Precision/Recall và số báo nhầm/bỏ sót trên các mục đã chuẩn hóa.
- **Thời gian:** báo riêng collector, thời gian mỗi câu của LLM/RAG và thời gian quét lab của Greenbone; không so trực tiếp một câu hỏi với một lượt quét toàn lab.

Kiểm tra source evidence và sự tồn tại của CVE từ nguồn chính thức. CVE vắng trong knowledge base chưa đủ để coi là bịa. Câu lỗi tính sai; trường hợp mẫu số 0 hoặc mã chưa xác minh ghi riêng trong báo cáo.

File question-plan.md có 100 câu dự thảo theo 16 instance aliases. Các CVE placeholders cần được điền bằng CVE có thật và expected answers phải được duyệt trước khi chấm. Đây là tài liệu gợi ý soạn test set, chưa phải 100 câu đã có ground truth.

## Bố cục và hiện trạng

Giữ năm mục: Giới thiệu bài toán → Dữ liệu → Phương pháp/kiến trúc (Indexing, Retrieval, Generation) → Baseline và thực nghiệm → Chỉ số đánh giá. PDF không có mục tài liệu tham khảo ở cuối.

Đã kiểm tra build đủ 16 bản, template CloudFormation, playbook Ansible và pilot OpenSSH → facts → LLM/RAG trên Codespace. Triển khai AWS, kiểm tra mạng liên máy, gold đã duyệt và benchmark đầy đủ vẫn chờ nghiệm thu; xem [audit hiện tại](../infra/aws/audit/IMPLEMENTATION.md). **11 kiểm tra chức năng trong báo cáo Docker cũ không phải Accuracy CVE hoặc kết quả AWS.**

Biên dịch bằng pdfLaTeX và các gói khai báo trong proposal.tex:

~~~bash
cd proposal
pdflatex -interaction=nonstopmode -halt-on-error proposal.tex
~~~

## Nguồn kiểm tra hai bản thực nghiệm

- FRRouting: [8.5.2](https://github.com/FRRouting/frr/releases/tag/frr-8.5.2), [9.0.1](https://github.com/FRRouting/frr/releases/tag/frr-9.0.1).
- nginx: [kho phát hành](https://nginx.org/download/) có 1.24.0 và 1.26.2.
- Apache: [advisory của nhánh 2.4](https://httpd.apache.org/security/vulnerabilities_24.html), gồm 2.4.49 và 2.4.50.
- BIND: [release notes 9.18.24](https://bind9.readthedocs.io/en/v9.18.24/notes.html), gồm ghi chú 9.18.19.
- OpenVPN: [2.6.8](https://github.com/OpenVPN/openvpn/releases/tag/v2.6.8), [2.6.10](https://github.com/OpenVPN/openvpn/releases/tag/v2.6.10).
- OpenSSH: [9.6](https://www.openssh.org/txt/release-9.6), [9.7](https://www.openssh.org/txt/release-9.7).
- HAProxy: [release archive 2.8](https://www.haproxy.org/download/2.8/src/) có 2.8.0 và 2.8.9.
- dnsmasq: [release archive](https://thekelleys.org.uk/dnsmasq/) có 2.86 và 2.90.
