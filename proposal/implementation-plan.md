# Kế hoạch triển khai AWS và thực nghiệm

Trạng thái: **đã có mã triển khai và kiểm tra cục bộ cho bước hạ tầng/collector**.
Ma trận 16 bản đã được build và kiểm tra version trên Ubuntu 22.04. CloudFormation,
CloudFormation điều phối Ansible qua SSH để cài native và lấy facts, không cần
agent thường trực. Đã chạy pilot OpenSSH/LLM/RAG local; triển khai AWS và benchmark
đầy đủ cùng các mốc gold/RAG/scanner vẫn chưa nghiệm thu.
Xem [audit](../infra/aws/audit/IMPLEMENTATION.md) và [pilot](../infra/aws/audit/PILOT.md).
Nguồn phạm vi: [proposal.tex](proposal.tex) và các yêu cầu bổ sung trong trao đổi.

## 1. Các yêu cầu đã chốt

- CloudFormation bao phủ đủ 8 phần mềm × 2 test versions = **16 tổ hợp**.
  Các bản chạy đồng thời và giữ cố định trong một đợt đánh giá.
- Có thể dùng nhiều template/stack; không bắt buộc nhét mọi tài nguyên vào một file.
- Khi triển khai, CloudFormation tự cài đúng phiên bản, ghi cấu hình, khởi động
  dịch vụ và gọi Ansible lấy facts/kiểm tra trạng thái. Tạo EC2 thành công chưa phải cài xong.
- Các máy thực hiện vai trò mạng: router chuyển tiếp lưu lượng, Web/Proxy phục vụ
  request, DNS trả lời truy vấn, VPN có tunnel và client sử dụng được dịch vụ.
- Collector thu thập toàn bộ thiết bị đã đăng ký; báo rõ máy thiếu, lỗi hoặc dữ liệu
  quá cũ. Ansible qua SSH là cách chính trên Linux; dùng module/adapter SSH/API/SNMP
  phù hợp nếu bổ sung appliance. Module facts đọc dữ liệu rồi thoát, không chạy daemon.
- Cùng VPC vẫn phải phân vùng: MGMT chỉ SSH quản trị; các nhánh client/dịch vụ có
  route riêng, luồng hợp lệ đi qua FRR, mỗi máy có ingress riêng và FRR default-deny
  forwarding. Kiểm tra cả kết nối được phép, kết nối phải bị chặn và counter router.
- Sau khi chuẩn bị và đóng băng dữ liệu, thực nghiệm chạy tự động: kiểm tra môi
  trường, lấy snapshot, chạy LLM/RAG, điều khiển Greenbone, chấm và xuất báo cáo.
- Từng mốc có thay đổi nhỏ, kiểm tra và bằng chứng để audit. Không coi kế hoạch,
  kiểm tra cấu hình hay kiểm tra mạng là kết quả đánh giá CVE.
- Giữ lõi embedding/Qdrant/retrieval/LLM client hiện có; bổ sung đầu vào inventory,
  phạm vi truy vấn và đầu ra theo thiết bị. Đổi catalog và nguồn advisory theo proposal.
- Benchmark chính bám các bản cài thực tế. Dataset bên ngoài chỉ được đưa vào khi
  xác minh phù hợp nhiệm vụ, sản phẩm, phiên bản và điều kiện; báo nguồn gốc riêng.

Phạm vi KB vẫn là 5 stable releases mới nhất mỗi phần mềm tại mốc thu thập,
cộng tài liệu cho test versions cũ nếu cần. Phạm vi triển khai là 16 tổ hợp dưới đây,
không phải triển khai tất cả phiên bản của KB.

## 2. Ma trận bắt buộc của CloudFormation

| Stack phần mềm dự kiến | Instance A | Instance B | Kiểm tra chức năng bắt buộc |
| --- | --- | --- | --- |
| `frr` | FRR-A / 8.5.2 | FRR-B / 9.0.1 | Version thực tế, daemon FRR, route và lưu lượng qua router |
| `nginx` | NGINX-A / 1.24.0 | NGINX-B / 1.26.2 | Version thực tế, cấu hình hiệu lực, request Web/Proxy |
| `apache` | APACHE-A / 2.4.49 | APACHE-B / 2.4.50 | Version thực tế, module/cấu hình, request HTTP |
| `bind` | BIND-A / 9.18.19 | BIND-B / 9.18.24 | Version thực tế, cấu hình/zone, truy vấn DNS |
| `openvpn` | OPENVPN-A / 2.6.8 | OPENVPN-B / 2.6.10 | Version thực tế, vai trò, tunnel và lưu lượng trong tunnel |
| `openssh` | OPENSSH-A / 9.6p1 | OPENSSH-B / 9.7p1 | Version Portable thực tế, cấu hình, phiên SSH server/client |
| `haproxy` | HAPROXY-A / 2.8.0 | HAPROXY-B / 2.8.9 | Version thực tế, cấu hình, request đi tới backend |
| `dnsmasq` | DNSMASQ-A / 2.86 | DNSMASQ-B / 2.90 | Version thực tế, cấu hình, truy vấn DNS |

Mỗi tổ hợp có device ID, IP/cổng và bằng chứng bản cài riêng. Hướng thiết kế ban
đầu là một EC2 riêng cho mỗi tổ hợp, cộng các máy quản trị/scanner/client cần thiết;
số máy phụ trợ và loại instance được xác định ở P1 trước khi triển khai AWS.
Không gộp hai phiên bản trên cùng endpoint hoặc thay phiên bản giữa các lượt chấm.

Ansible/collector đọc package và binary/cấu hình được hỗ trợ; phạm vi chấm được khai báo riêng.
OpenSSH hoặc các dependency phục vụ quản trị không tự động trở thành một trong
16 target instances. Giữ thông tin chúng trong inventory để không nhầm binary,
dịch vụ hoặc cổng của bản thực nghiệm với bản do hệ điều hành cung cấp.

## 3. Cách chia CloudFormation

Phân chia dự kiến ban đầu ở bảng dưới. Bản hiện thực dùng một template target
chung với 16 nested stacks để tránh trùng code; các template thực tế nằm tại
[`infra/aws/templates/`](../infra/aws/templates/).

| Thành phần | Trách nhiệm |
| --- | --- |
| `infra/aws/network.yaml` | VPC, subnet, route, security group và kết nối giữa các vai trò |
| `infra/aws/management.yaml` | Máy MGMT, collector, dịch vụ RAG và lưu trữ/cấu hình cần thiết |
| `infra/aws/products/*.yaml` | Stack từng phần mềm, tạo đủ hai bản và cấu hình vai trò tương ứng |
| `infra/aws/scanner.yaml` | Greenbone/OpenVAS, kết nối quản lý, cấu hình truy cập target |
| `infra/aws/root.yaml` | Điều phối các stack con và xuất inventory/endpoint phục vụ runner |
| `infra/aws/bootstrap.py`, `infra/ansible/` | Cài phiên bản cố định, cấu hình dịch vụ, facts qua SSH và readiness |

Có thể dùng template thành phần chung để giảm trùng lặp. Entry point mặc định
phải triển khai được đủ 16 tổ hợp; chạy riêng một stack phục vụ phát triển không
được báo là đã hoàn tất môi trường thực nghiệm.

Bootstrap phải dùng nguồn và checksum đã khóa; package/build dependencies và
cấu hình phải truy vết được. Khi thiếu bản cài hoặc build lỗi, phải báo lỗi thay
vì chuyển sang phiên bản mới nhất. Readiness gồm cài đặt, dịch vụ, kết nối cần
thiết và snapshot đầu tiên được collector tiếp nhận. Kiểm tra liên máy được chạy
sau khi các node liên quan sẵn sàng; tách dependency để tránh vòng chờ bootstrap.

Nếu có bước publish bootstrap/template lên S3 hoặc chuẩn bị image/artifact trước
deploy, bước đó cũng nằm trong công cụ tự động và ghi manifest; người dùng không
phải SSH vào các máy để cài tiếp. Collector và các máy được đánh giá triển khai
trong mạng private với đường quản trị được khai báo.

Router phải nằm trên đường truyền dữ liệu, không chỉ là EC2 mang nhãn router.
Nếu dùng native VPC routing, cần route hai chiều qua appliance và tắt
source/destination check phù hợp. Nếu cần giao thức/hành vi Layer 2, chọn mạng
overlay và kiểm tra riêng ở P1.

Switch trong proposal hiện chỉ minh họa kết nối, chưa có OS/firmware trong danh
sách chấm CVE. Nếu bổ sung switch ảo có cấu hình/phần mềm để collector đọc, cần
ghi rõ triển khai và giới hạn; không coi VPC subnet là switch firmware tự quản lý.
Quyết định dùng switch ảo/overlay hay chỉ kết nối VPC sẽ được ghi trong audit P1.

## 4. Các mốc triển khai và audit

| Mốc | Công việc | Điều kiện nghiệm thu | Bằng chứng |
| --- | --- | --- | --- |
| P0 | Ghi yêu cầu, ma trận và thứ tự thực hiện | Đủ 16 tổ hợp, phân biệt kế hoạch với kết quả đã chạy | Tài liệu này |
| P1 | Khóa manifest triển khai và topology | Đủ 16 bản có nguồn/checksum, OS/architecture/build strategy, role/IP/cổng và probe; chốt route/switch và cấu hình thực nghiệm | Manifest, kiểm tra build, audit quyết định |
| P2 | Viết CloudFormation và bootstrap đủ ma trận | Template hợp lệ; sau deploy đủ 16 bản, dịch vụ và luồng mạng đúng; thiếu/lỗi làm readiness thất bại | Kết quả validation, stack events, log bootstrap, version/probe results |
| P3 | Collector và Ansible/adapter | Đủ target đăng ký, đúng product/version/component/config; thử được lỗi, snapshot cũ, trùng danh tính và mất kết nối | Inventory kỳ vọng, raw facts, coverage report |
| P4 | Xây và đóng băng gold | Bản cài đã kiểm chứng + evidence đã duyệt; câu hỏi sinh đúng scope; bộ gold tách khỏi RAG | Source snapshot, bảng gold, review record, dataset hash |
| P5 | Tích hợp inventory với RAG | Hỏi từng máy/nhóm/toàn mạng, kết luận và citation gắn đúng target; thiếu dữ kiện trả chưa đủ bằng chứng | Test tích hợp và response có truy vết |
| P6 | Runner thực nghiệm và Greenbone | Một luồng tự động từ preflight tới báo cáo; không nhập tay kết quả, IP hoặc đáp án giữa lượt chạy | Run manifest, raw output, log API, kết quả chuẩn hóa, summary |
| P7 | Audit toàn quy trình và chạy đủ test set | Đủ 16 tổ hợp và 100 câu đã duyệt; lỗi không bị loại để làm tăng điểm; báo cáo tái chấm được | Audit cuối, metrics, artifact hashes và báo cáo |

Trong từng mốc có thể kiểm tra trước trên số node nhỏ, nhưng phạm vi nghiệm thu
P2/P3/P7 vẫn phải đủ ma trận. Chỉ chuyển mốc khi kiểm tra liên quan đạt; sửa lỗi
và audit trong chính mốc đang làm. Việc này là kiểm soát chất lượng theo từng bước,
không tạo thêm yêu cầu xác nhận thủ công giữa các câu hỏi thực nghiệm.

Mỗi audit ghi: yêu cầu được kiểm tra, file thay đổi, môi trường/lệnh, kết quả
`passed`/`failed`/`pending`/`skipped`, artifact liên quan, hạn chế và việc còn lại.
Kiểm tra chưa chạy phải để `pending`/`skipped`, không suy ra PASS từ template.

## 5. Ground truth ít thao tác tay

1. Manifest triển khai mô tả cấu hình mong muốn. Probe bản cài độc lập xác nhận
   binary, package/build, thành phần và cấu hình thực tế trước khi tạo gold.
2. Từ CVE/advisory chính thức, lập evidence cho từng kết luận, gồm version range,
   platform/configuration cần thiết và source URL/đoạn nội dung. Ưu tiên dữ liệu
   máy đọc được khi nguồn cung cấp, nhưng vẫn kiểm tra điều kiện áp dụng.
3. Duyệt các bằng chứng/rule duy nhất rồi tái sử dụng khi sinh đáp án. Không nhập
   lại 100 đáp án bằng tay; không lấy đầu ra RAG/LLM/Greenbone làm nhãn chuẩn.
4. Dùng bảng đã duyệt để sinh câu hỏi và expected findings theo scope. Bộ sinh
   gold tách khỏi logic matcher của RAG; lưu các kết luận rõ ràng và kiểm tra
   độc lập các trường hợp biên để tránh sao chép cùng một lỗi.
5. Tách `affected`, `not_affected`, `insufficient_evidence`. Không suy không ảnh
   hưởng từ việc CVE không xuất hiện trong KB hoặc một kết quả quét.
6. Khóa dataset/evidence trước benchmark. Vòng chạy chính thức chỉ dùng bộ đã
   duyệt; thiếu gold thì dừng preflight, không nhờ LLM tự điền nhãn khi đang chấm.

Benchmark cần khai báo rõ tập CVE/ngày chốt. Nếu chọn tập CVE giới hạn, câu hỏi
phải thể hiện phạm vi đó; không chấm như đã bao phủ mọi lỗ hổng của phiên bản.
Mã ngoài tập gold cần được phân loại/xác minh thay vì tự kết luận là không tồn tại.

Dataset bên ngoài cần được kiểm tra theo product/version/component/platform,
định dạng nhiệm vụ, nguồn gốc và điều kiện sử dụng. Báo riêng dữ liệu nguyên bản
với dữ liệu đã điều chỉnh cho mạng AWS. Không giả định một bộ public bao phủ đủ
16 tổ hợp. Các câu dùng chung thiết bị/CVE không được xem là trạng thái mạng độc lập.

Review evidence là công việc chuẩn bị một lần và khi nguồn/phạm vi thay đổi.
Khâu chạy thực nghiệm không cần người sửa đáp án hoặc đọc từng câu để tiếp tục.
Kiểm tra ngữ nghĩa lời văn/citation chưa tự động xác minh được phải được báo rõ
và có tập audit riêng, không gán URL trùng thành citation correctness.

Cách diễn đạt test set trong proposal hiện là “nhóm tự viết”. Khi quy trình sinh
câu hỏi từ bảng gold được chốt, cần đồng bộ mô tả phương pháp trong tài liệu;
P0 chưa thay đổi nguồn LaTeX/PDF.

## 6. Luồng thực nghiệm tự động

Runner dự kiến điều phối tuần tự:

1. Preflight: stack/probe/collector đủ 16 tổ hợp, gold đã duyệt, KB và cấu hình
   model/feed được khóa. Nếu cần chuẩn bị KB/feed, hoàn tất trước khi khóa lượt chạy.
2. Chụp inventory/config snapshot; xác minh khớp trạng thái bản cài đã dùng cho gold.
3. Chạy LLM và RAG trên cùng câu hỏi, thông tin máy, model và tham số. Chỉ RAG
   nhận thêm evidence từ KB; cả hai không nhận gold labels.
4. Tự cấu hình/chạy/theo dõi Greenbone qua API quản lý, lưu raw report và kiểm tra
   quyền truy cập từng target. Không cần thao tác Web UI hay xuất XML bằng tay.
5. Kiểm tra drift cấu hình/phiên bản sau lượt chạy. Nếu thay đổi thì đánh dấu lượt
   không hợp lệ để không ghép kết quả từ những trạng thái mạng khác nhau.
6. Chuẩn hóa kết quả theo `(device_id, product_id, version, CVE)` và scope mỗi câu.
   Lưu trạng thái kết luận riêng; không tính mọi CVE được nhắc là CVE ảnh hưởng.
7. Tự chấm và xuất báo cáo, raw outputs, lỗi, coverage và manifest để tái chấm.

Lưu ý khi so sánh: lần quét Greenbone toàn mạng được lọc theo scope từng câu,
không phải thực hiện 100 lần quét. Ca không có VT hỗ trợ/lỗi truy cập được báo
coverage riêng; CVE thực sự ảnh hưởng nhưng không được phát hiện vẫn là FN.
Lưu feed/version, scan configuration, xác thực thành công hay không, QoD và mapping.

Run manifest ghi phiên bản code và dấu vết thay đổi chưa commit, stack IDs,
16 target identities, version/build/config hashes, inventory snapshot, KB/dataset
hashes, model/tham số, feed/scan metadata, mốc thời gian và trạng thái hoàn thành.
Resume chỉ tái sử dụng kết quả khi các đầu vào đã khóa còn khớp. Lượt thiếu kết quả
phải hiện là chưa hoàn thành; lần chạy chính thức tính câu lỗi là sai, không chỉ
chấm các cặp trả lời thành công. Giữ báo cáo phụ cho các cặp thành công nếu cần.

Các số liệu chính: Accuracy toàn câu, Precision/Recall/TP/FP/FN theo findings,
citation correctness/coverage theo evidence, CVE hallucination dựa trên xác minh
chính thức. Mã chưa xác minh và mẫu số 0 được báo riêng. Latency tách collector,
mỗi câu LLM/RAG và toàn lượt quét; giữ thông tin retry, thời gian chờ và lỗi.

## 7. Những việc cần xác minh ở P1

- Khả năng build đúng cả 16 bản trên OS/architecture đã chọn, không dựa vào
  package mặc định tình cờ có sẵn trong AMI.
- Cấu hình và vai trò server/client cụ thể, nhất là OpenVPN và OpenSSH;
  các phiên bản không tự động được gắn nhãn “có lỗi” hoặc “đã sửa”.
- Topology, route hai chiều qua FRR, lựa chọn switch/overlay và số máy phụ trợ.
- Region, loại instance, dung lượng cho scanner/KB và dự toán trước triển khai AWS.
- Các CVE có bằng chứng rõ cho test versions; phạm vi tập gold và mức bao phủ của
  dataset ngoài. Chưa có bộ ngoài nào được xác nhận bao phủ đủ 16 tổ hợp.
- Chính sách chọn 5 stable releases và nguồn advisory/CPE cho đủ 8 sản phẩm;
  không ảnh hưởng việc giữ nguyên 16 test versions trong bảng.

## 8. Nguồn kỹ thuật cho thiết kế

- [CloudFormation CreationPolicy](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-attribute-creationpolicy.html): chờ tín hiệu hoàn tất cấu hình tài nguyên.
- [VPC routing qua appliance](https://docs.aws.amazon.com/vpc/latest/userguide/route-table-options.html): route và source/destination checking.
- [Layer 2 trên EC2](https://aws.amazon.com/blogs/networking-and-content-delivery/setting-up-layer-2-networking-on-amazon-ec2/): giới hạn VPC và các cách triển khai overlay.
- [Greenbone scanning](https://docs.greenbone.net/GSM-Manual/gos-24.10/en/scanning.html): thu thập có xác thực trên Linux và thiết bị mạng.
