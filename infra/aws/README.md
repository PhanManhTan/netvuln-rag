# AWS experiment: CloudFormation + Ansible

CloudFormation tạo hạ tầng và tự gọi Ansible để cài đủ **16 bản trong proposal**,
khởi động dịch vụ, lấy facts và kiểm tra mạng. Phần mềm cài native trên từng EC2;
không cần tạo Docker image. Ansible dùng SSH qua IP private, không cài agent thường
trực. MGMT dùng Ubuntu 24.04/Python 3.12; 16 target dùng Ubuntu 22.04 x86_64.

Đã kiểm tra build đủ 16 bản, template và playbook local. Pilot OpenSSH đã thu facts
bằng Ansible và chạy LLM/RAG. **Chưa tạo tài nguyên AWS**; route, firewall, VPN và BGP
liên máy chưa được nghiệm thu. Xem [audit](audit/IMPLEMENTATION.md) và [pilot](audit/PILOT.md).
Greenbone, gold đã duyệt, inventory tổng quát cho RAG và benchmark đầy đủ nằm trong
[kế hoạch](../../proposal/implementation-plan.md).

## Ma trận cài đặt

[experiment.json](experiment.json) là inventory kỳ vọng. Facts phải đọc từ máy thật.

| Phần mềm | A | B |
| --- | --- | --- |
| FRRouting | 8.5.2 | 9.0.1 |
| nginx | 1.24.0 | 1.26.2 |
| Apache HTTP Server | 2.4.49 | 2.4.50 |
| BIND | 9.18.19 | 9.18.24 |
| OpenVPN | 2.6.8 | 2.6.10 |
| OpenSSH Portable | 9.6p1 | 9.7p1 |
| HAProxy | 2.8.0 | 2.8.9 |
| dnsmasq | 2.86 | 2.90 |

## Phân vùng mạng trong một VPC

Các subnet quản trị, router, client A/B và dịch vụ A/B có route table riêng.
Mỗi target có security group riêng; không có inbound cho phép toàn VPC.
MGMT được SSH quản trị cổng 22 vào các target bằng khóa riêng. Workload không
được khởi tạo kết nối vào MGMT. Không mở public ingress.

| Nguồn → đích | Cho phép | Đường đi |
| --- | --- | --- |
| MGMT → tất cả target | TCP 22 | Mạng quản trị private |
| Client OpenSSH A/B → HAProxy cùng nhánh | HTTP 80 | FRR A/B → HAProxy → nginx → Apache |
| Client → dnsmasq cùng nhánh | UDP/TCP 53 | FRR A/B → dnsmasq → BIND |
| Client → Apache cùng nhánh | SSH 22, tài khoản probe không sudo | FRR A/B; kiểm tra binary SSH client |
| HAProxy → nginx; nginx → Apache | HTTP 80, đúng peer | Subnet dịch vụ cùng nhánh |
| dnsmasq → BIND | UDP/TCP 53, đúng peer | Subnet dịch vụ cùng nhánh |
| OpenVPN-B → OpenVPN-A | UDP 1194 | FRR-A, sau đó kiểm tra tunnel |
| FRR-A ↔ FRR-B | BGP TCP 179 | Subnet router |

Các luồng khác bị chặn theo ingress của đích. FRR còn có firewall nftables mặc
định chặn forwarding ngoài các luồng trong [network_policy.py](network_policy.py).
Client/dịch vụ cùng nhánh có route hai chiều qua cùng FRR, tắt source/destination
check ở router. Egress bootstrap vẫn mở qua NAT; chưa lọc mọi truy cập Internet.
DNS mặc định AWS cũng không được coi là bị chặn bởi policy DNS dịch vụ này.

Probe kiểm tra cả kết nối được phép và kết nối bị cấm: client không gọi thẳng
HTTP backend, không sang nhánh khác, không SSH vào MGMT; HAProxy không bỏ qua nginx;
backend không quản trị client. Connection refused không được chấm là bằng chứng
firewall chặn. Counter FRR phải tăng so với baseline trước probe trong cùng lượt;
counter tích lũy từ lượt trước không đủ chứng minh đường đi hiện tại.

VPC là fabric do AWS quản lý; chưa mô phỏng firmware switch, VLAN/STP hoặc appliance
thương mại. Xem AWS về [route qua appliance giữa subnet](https://docs.aws.amazon.com/vpc/latest/userguide/intra-vpc-route.html)
và [security group với middlebox](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html).

## Thứ tự triển khai tự động

1. Stack artifacts tùy chọn tạo bucket private, mã hóa, versioning và giữ dữ liệu khi xóa stack.
2. Root tạo network: VPC, subnet, route table, security group, NAT và S3 endpoint.
3. Management cài Ansible, tạo khóa SSH quản trị và probe riêng, host keys đã biết trước,
   chứng thư VPN; upload bundle PKI riêng cho từng node.
4. 16 stack target chuẩn bị Python/SSH, tài khoản Ansible và sudo; mỗi node chỉ đọc PKI của mình.
5. Root tạo route và gọi FleetReadiness qua SSM trên MGMT. Ansible cài dependency,
   build source đã khóa khi cần, cấu hình systemd, lấy OS/package/binary/config/network
   facts, chạy probe dịch vụ/phân vùng rồi lấy counter FRR.
6. MGMT lưu raw facts, log, snapshot immutable và coverage lên S3. Chỉ khi đủ 16 máy
   đúng bản, dịch vụ hoạt động và probe qua thì readiness thành công.

CloudFormation không tự có stage thực nghiệm: dependency và cổng kiểm tra trên
được khai báo trong template/code. Ansible có thể chạy lại trên fleet đang có:
binary đúng version/hash/source thì bỏ qua build; cấu hình được giữ đúng trạng
thái mong muốn và facts được thu mới.

## Kiểm tra và đóng gói local

Dùng Python môi trường dự án; aws extra có SDK/cfn-lint. Ansible control dùng
Python 3.12 và [control-requirements.txt](control-requirements.txt).

~~~bash
python -m infra.aws.sources
python -m infra.aws.render
python -m pytest -q
cfn-lint infra/aws/templates/*.template.json
python -m infra.aws.package
python -m infra.aws.deploy --region us-east-1 --stack-name netvuln-exp-001
~~~

Lệnh deploy trên chỉ ghi plan, **không gọi AWS**. Cache và artifact nằm trong
artifacts/aws/, được gitignore. [sources.lock.json](sources.lock.json) khóa 17 archive
chính thức bằng SHA-256 quan sát qua HTTPS; chưa xác minh chữ ký nhà phát hành.
Bundle chỉ lấy code/cấu hình cho phép và archive đã khóa; không chứa .env,
credentials, khóa riêng hoặc gold. Chưa có KB/RAG/scanner trong bundle.

Bằng chứng build 16 bản trên Ubuntu 22.04 ở [build-results.json](audit/build-results.json).
Các image kiểm tra tạm đã xóa theo yêu cầu; deployment không dùng chúng.
Có thể build native bằng python -m infra.aws.build --help; EC2 dùng cùng recipe.
Apt dependencies chưa khóa thành snapshot tái tạo binary từng bit; inventory ghi
lại các package thực cài.

Pilot local cho bản OpenSSH đã cài và đang chạy riêng trên loopback:

~~~bash
ANSIBLE_HOME=/tmp/netvuln-ansible-home ANSIBLE_CONFIG=infra/ansible/ansible.cfg ansible-playbook -i localhost, infra/ansible/pilot.yml
python -m evaluation.pilot
~~~

Playbook cần sudo để đọc tiến trình/cấu hình sshd root. Nó không tạo firewall,
route hoặc thay sshd hệ thống trên Codespace. Điều kiện chuẩn bị binary và service
riêng được ghi trong [báo cáo pilot](audit/PILOT.md).

## Chạy AWS và audit

~~~bash
python -m infra.aws.deploy --region us-east-1 --stack-name netvuln-exp-001 --execute
~~~

--execute tạo **17 EC2, 1 NAT Gateway, EBS và tài nguyên liên quan**, chưa gồm
Greenbone. Bỏ qua bucket thì launcher tạo stack artifact. Bỏ qua AMI thì nó tra SSM
Canonical một lần, kiểm tra và lưu ID cụ thể cho target 22.04/control 24.04. Có thể
truyền --ami-id và --control-ami-id đã khóa. Region tạm là us-east-1 theo “us 1”.
Chưa dự toán giá hoặc kiểm tra quota tự động; cần quyền
CloudFormation/IAM/EC2/VPC/SSM/S3 tương ứng.

Launcher chỉ tạo fleet mới cho bundle mới, không update cloud-init của stack cũ.
Để thu lại/khôi phục cùng bản cài đã khóa, chạy trên MGMT qua SSM:

~~~bash
cd /opt/netvuln/repo
sudo /opt/netvuln/venv/bin/python -m infra.aws.ansible_control --config /etc/netvuln/bootstrap.json
~~~

Mỗi lần chạy có thư mục riêng /var/lib/netvuln/ansible/<run>/ và S3
<ArtifactsPrefix>/runs/ansible/<run>/: inventory, log, raw facts, snapshots,
probes, router counters và summary.json. Thiếu máy, stale snapshot, sai binary
hoặc probe lỗi làm complete=false. Xem stack events, /var/log/cloud-init-output.log,
journal netvuln-target/netvuln-firewall và build.json ở prefix của sản phẩm.

Khóa quản trị riêng ở MGMT, không phân phối xuống target. PKI trên S3 là dữ liệu
nhạy cảm, không đưa vào báo cáo công khai. Bucket artifact được giữ khi xóa stack;
xóa fleet và dữ liệu giữ lại là các thao tác riêng của operator.
