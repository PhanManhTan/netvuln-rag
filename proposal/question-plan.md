# 100 câu hỏi dự thảo cho evaluation

Các câu dưới đây dùng inventory dự kiến gồm 8 software × 2 versions, giữ cố định trong cùng hệ thống mạng. Đây là question draft; expected answers được duyệt từ bản cài/configuration và advisory trước khi đưa vào test set.

## Inventory aliases

| Software | Instance A / version | Instance B / version |
| --- | --- | --- |
| FRRouting | FRR-A / 8.5.2 | FRR-B / 9.0.1 |
| nginx | NGINX-A / 1.24.0 | NGINX-B / 1.26.2 |
| Apache HTTP Server | APACHE-A / 2.4.49 | APACHE-B / 2.4.50 |
| BIND 9 | BIND-A / 9.18.19 | BIND-B / 9.18.24 |
| OpenVPN | OPENVPN-A / 2.6.8 | OPENVPN-B / 2.6.10 |
| OpenSSH Portable | OPENSSH-A / 9.6p1 | OPENSSH-B / 9.7p1 |
| HAProxy | HAPROXY-A / 2.8.0 | HAPROXY-B / 2.8.9 |
| dnsmasq | DNSMASQ-A / 2.86 | DNSMASQ-B / 2.90 |

## Chuẩn bị câu hỏi và expected answers

- Thay aliases bằng device/instance ID thực tế trong collector. Nếu nhiều instance cùng VM, giữ ID riêng và thông tin IP/port tương ứng.
- Điền {CVE_PRODUCT_1}, {CVE_PRODUCT_2} bằng hai CVE ID có thật từ advisory của software đó. Chọn các trường hợp có phạm vi version/configuration rõ, gồm kết luận áp dụng và không áp dụng khi có thể.
- {CVE_NEGATIVE} là một CVE có thật nhưng không áp dụng cho các software/version đã cài, được người kiểm tra xác nhận trước.
- Với câu hỏi configuration/platform, chỉ dùng điều kiện advisory thực sự nêu; collector lấy thêm field cần thiết cho điều kiện đó. Không thay configuration giữa các lượt đánh giá.
- Mỗi expected answer lưu device, software, version, CVE set/kết luận và source URL/đoạn evidence. Thành viên khác duyệt; expected answers lưu riêng khỏi knowledge base.
- Các nhóm bao phủ cách hỏi và scope khác nhau trên cùng hệ thống. Ghi kết quả theo nhóm, software và CVE để biết lỗi tập trung ở đâu; 100 câu không được xem là 100 trạng thái mạng độc lập.

## A. CVE theo từng instance — 16 câu

| ID | Câu hỏi |
| --- | --- |
| Q001 | FRR-A đang chạy FRRouting 8.5.2. Instance này có những CVE đã công bố nào áp dụng? Liệt kê kèm source. |
| Q002 | FRR-B đang chạy FRRouting 9.0.1. Instance này có những CVE đã công bố nào áp dụng? Liệt kê kèm source. |
| Q003 | NGINX-A đang chạy nginx 1.24.0. Instance này có những CVE đã công bố nào áp dụng? Liệt kê kèm source. |
| Q004 | NGINX-B đang chạy nginx 1.26.2. Instance này có những CVE đã công bố nào áp dụng? Liệt kê kèm source. |
| Q005 | APACHE-A đang chạy Apache HTTP Server 2.4.49. Instance này có những CVE đã công bố nào áp dụng? Liệt kê kèm source. |
| Q006 | APACHE-B đang chạy Apache HTTP Server 2.4.50. Instance này có những CVE đã công bố nào áp dụng? Liệt kê kèm source. |
| Q007 | BIND-A đang chạy BIND 9 9.18.19. Instance này có những CVE đã công bố nào áp dụng? Liệt kê kèm source. |
| Q008 | BIND-B đang chạy BIND 9 9.18.24. Instance này có những CVE đã công bố nào áp dụng? Liệt kê kèm source. |
| Q009 | OPENVPN-A đang chạy OpenVPN 2.6.8. Instance này có những CVE đã công bố nào áp dụng? Liệt kê kèm source. |
| Q010 | OPENVPN-B đang chạy OpenVPN 2.6.10. Instance này có những CVE đã công bố nào áp dụng? Liệt kê kèm source. |
| Q011 | OPENSSH-A đang chạy OpenSSH Portable 9.6p1. Instance này có những CVE đã công bố nào áp dụng? Liệt kê kèm source. |
| Q012 | OPENSSH-B đang chạy OpenSSH Portable 9.7p1. Instance này có những CVE đã công bố nào áp dụng? Liệt kê kèm source. |
| Q013 | HAPROXY-A đang chạy HAProxy 2.8.0. Instance này có những CVE đã công bố nào áp dụng? Liệt kê kèm source. |
| Q014 | HAPROXY-B đang chạy HAProxy 2.8.9. Instance này có những CVE đã công bố nào áp dụng? Liệt kê kèm source. |
| Q015 | DNSMASQ-A đang chạy dnsmasq 2.86. Instance này có những CVE đã công bố nào áp dụng? Liệt kê kèm source. |
| Q016 | DNSMASQ-B đang chạy dnsmasq 2.90. Instance này có những CVE đã công bố nào áp dụng? Liệt kê kèm source. |

## B. Tra một CVE cụ thể trên một instance — 16 câu

| ID | Câu hỏi |
| --- | --- |
| Q017 | {CVE_FRR_1} có áp dụng cho FRRouting 8.5.2 trên FRR-A không? Nêu kết luận và source. |
| Q018 | {CVE_FRR_2} có áp dụng cho FRRouting 9.0.1 trên FRR-B không? Nêu kết luận và source. |
| Q019 | {CVE_NGINX_1} có áp dụng cho nginx 1.24.0 trên NGINX-A không? Nêu kết luận và source. |
| Q020 | {CVE_NGINX_2} có áp dụng cho nginx 1.26.2 trên NGINX-B không? Nêu kết luận và source. |
| Q021 | {CVE_APACHE_1} có áp dụng cho Apache HTTP Server 2.4.49 trên APACHE-A không? Nêu kết luận và source. |
| Q022 | {CVE_APACHE_2} có áp dụng cho Apache HTTP Server 2.4.50 trên APACHE-B không? Nêu kết luận và source. |
| Q023 | {CVE_BIND_1} có áp dụng cho BIND 9 9.18.19 trên BIND-A không? Nêu kết luận và source. |
| Q024 | {CVE_BIND_2} có áp dụng cho BIND 9 9.18.24 trên BIND-B không? Nêu kết luận và source. |
| Q025 | {CVE_OPENVPN_1} có áp dụng cho OpenVPN 2.6.8 trên OPENVPN-A không? Nêu kết luận và source. |
| Q026 | {CVE_OPENVPN_2} có áp dụng cho OpenVPN 2.6.10 trên OPENVPN-B không? Nêu kết luận và source. |
| Q027 | {CVE_OPENSSH_1} có áp dụng cho OpenSSH Portable 9.6p1 trên OPENSSH-A không? Nêu kết luận và source. |
| Q028 | {CVE_OPENSSH_2} có áp dụng cho OpenSSH Portable 9.7p1 trên OPENSSH-B không? Nêu kết luận và source. |
| Q029 | {CVE_HAPROXY_1} có áp dụng cho HAProxy 2.8.0 trên HAPROXY-A không? Nêu kết luận và source. |
| Q030 | {CVE_HAPROXY_2} có áp dụng cho HAProxy 2.8.9 trên HAPROXY-B không? Nêu kết luận và source. |
| Q031 | {CVE_DNSMASQ_1} có áp dụng cho dnsmasq 2.86 trên DNSMASQ-A không? Nêu kết luận và source. |
| Q032 | {CVE_DNSMASQ_2} có áp dụng cho dnsmasq 2.90 trên DNSMASQ-B không? Nêu kết luận và source. |

## C. Điều kiện áp dụng — 16 câu

| ID | Câu hỏi |
| --- | --- |
| Q033 | Với {CVE_FRR_2}, configuration hoặc platform hiện tại của FRR-A có thỏa điều kiện trong advisory không? Chỉ ra dữ kiện liên quan. |
| Q034 | Với {CVE_FRR_1}, configuration hoặc platform hiện tại của FRR-B có thỏa điều kiện trong advisory không? Chỉ ra dữ kiện liên quan. |
| Q035 | Với {CVE_NGINX_2}, configuration hoặc platform hiện tại của NGINX-A có thỏa điều kiện trong advisory không? Chỉ ra dữ kiện liên quan. |
| Q036 | Với {CVE_NGINX_1}, configuration hoặc platform hiện tại của NGINX-B có thỏa điều kiện trong advisory không? Chỉ ra dữ kiện liên quan. |
| Q037 | Với {CVE_APACHE_2}, configuration hoặc platform hiện tại của APACHE-A có thỏa điều kiện trong advisory không? Chỉ ra dữ kiện liên quan. |
| Q038 | Với {CVE_APACHE_1}, configuration hoặc platform hiện tại của APACHE-B có thỏa điều kiện trong advisory không? Chỉ ra dữ kiện liên quan. |
| Q039 | Với {CVE_BIND_2}, configuration hoặc platform hiện tại của BIND-A có thỏa điều kiện trong advisory không? Chỉ ra dữ kiện liên quan. |
| Q040 | Với {CVE_BIND_1}, configuration hoặc platform hiện tại của BIND-B có thỏa điều kiện trong advisory không? Chỉ ra dữ kiện liên quan. |
| Q041 | Với {CVE_OPENVPN_2}, configuration hoặc platform hiện tại của OPENVPN-A có thỏa điều kiện trong advisory không? Chỉ ra dữ kiện liên quan. |
| Q042 | Với {CVE_OPENVPN_1}, configuration hoặc platform hiện tại của OPENVPN-B có thỏa điều kiện trong advisory không? Chỉ ra dữ kiện liên quan. |
| Q043 | Với {CVE_OPENSSH_2}, configuration hoặc platform hiện tại của OPENSSH-A có thỏa điều kiện trong advisory không? Chỉ ra dữ kiện liên quan. |
| Q044 | Với {CVE_OPENSSH_1}, configuration hoặc platform hiện tại của OPENSSH-B có thỏa điều kiện trong advisory không? Chỉ ra dữ kiện liên quan. |
| Q045 | Với {CVE_HAPROXY_2}, configuration hoặc platform hiện tại của HAPROXY-A có thỏa điều kiện trong advisory không? Chỉ ra dữ kiện liên quan. |
| Q046 | Với {CVE_HAPROXY_1}, configuration hoặc platform hiện tại của HAPROXY-B có thỏa điều kiện trong advisory không? Chỉ ra dữ kiện liên quan. |
| Q047 | Với {CVE_DNSMASQ_2}, configuration hoặc platform hiện tại của DNSMASQ-A có thỏa điều kiện trong advisory không? Chỉ ra dữ kiện liên quan. |
| Q048 | Với {CVE_DNSMASQ_1}, configuration hoặc platform hiện tại của DNSMASQ-B có thỏa điều kiện trong advisory không? Chỉ ra dữ kiện liên quan. |

## D. Kiểm chứng kết luận bằng evidence — 16 câu

| ID | Câu hỏi |
| --- | --- |
| Q049 | Đưa source URL và đoạn nội dung chứng minh kết luận về {CVE_FRR_1} trên FRR-A; liên hệ với version 8.5.2 collector đọc được. |
| Q050 | Đưa source URL và đoạn nội dung chứng minh kết luận về {CVE_FRR_2} trên FRR-B; liên hệ với version 9.0.1 collector đọc được. |
| Q051 | Đưa source URL và đoạn nội dung chứng minh kết luận về {CVE_NGINX_1} trên NGINX-A; liên hệ với version 1.24.0 collector đọc được. |
| Q052 | Đưa source URL và đoạn nội dung chứng minh kết luận về {CVE_NGINX_2} trên NGINX-B; liên hệ với version 1.26.2 collector đọc được. |
| Q053 | Đưa source URL và đoạn nội dung chứng minh kết luận về {CVE_APACHE_1} trên APACHE-A; liên hệ với version 2.4.49 collector đọc được. |
| Q054 | Đưa source URL và đoạn nội dung chứng minh kết luận về {CVE_APACHE_2} trên APACHE-B; liên hệ với version 2.4.50 collector đọc được. |
| Q055 | Đưa source URL và đoạn nội dung chứng minh kết luận về {CVE_BIND_1} trên BIND-A; liên hệ với version 9.18.19 collector đọc được. |
| Q056 | Đưa source URL và đoạn nội dung chứng minh kết luận về {CVE_BIND_2} trên BIND-B; liên hệ với version 9.18.24 collector đọc được. |
| Q057 | Đưa source URL và đoạn nội dung chứng minh kết luận về {CVE_OPENVPN_1} trên OPENVPN-A; liên hệ với version 2.6.8 collector đọc được. |
| Q058 | Đưa source URL và đoạn nội dung chứng minh kết luận về {CVE_OPENVPN_2} trên OPENVPN-B; liên hệ với version 2.6.10 collector đọc được. |
| Q059 | Đưa source URL và đoạn nội dung chứng minh kết luận về {CVE_OPENSSH_1} trên OPENSSH-A; liên hệ với version 9.6p1 collector đọc được. |
| Q060 | Đưa source URL và đoạn nội dung chứng minh kết luận về {CVE_OPENSSH_2} trên OPENSSH-B; liên hệ với version 9.7p1 collector đọc được. |
| Q061 | Đưa source URL và đoạn nội dung chứng minh kết luận về {CVE_HAPROXY_1} trên HAPROXY-A; liên hệ với version 2.8.0 collector đọc được. |
| Q062 | Đưa source URL và đoạn nội dung chứng minh kết luận về {CVE_HAPROXY_2} trên HAPROXY-B; liên hệ với version 2.8.9 collector đọc được. |
| Q063 | Đưa source URL và đoạn nội dung chứng minh kết luận về {CVE_DNSMASQ_1} trên DNSMASQ-A; liên hệ với version 2.86 collector đọc được. |
| Q064 | Đưa source URL và đoạn nội dung chứng minh kết luận về {CVE_DNSMASQ_2} trên DNSMASQ-B; liên hệ với version 2.90 collector đọc được. |

## E. Tổng hợp theo software — 16 câu

| ID | Câu hỏi |
| --- | --- |
| Q065 | Trong mạng, những instance nào chạy FRRouting, và từng instance liên quan những CVE nào? Nhóm theo device và version. |
| Q066 | {CVE_FRR_1} ảnh hưởng đến những instance FRRouting nào trong mạng? Nêu version và source cho từng kết luận. |
| Q067 | Trong mạng, những instance nào chạy nginx, và từng instance liên quan những CVE nào? Nhóm theo device và version. |
| Q068 | {CVE_NGINX_1} ảnh hưởng đến những instance nginx nào trong mạng? Nêu version và source cho từng kết luận. |
| Q069 | Trong mạng, những instance nào chạy Apache HTTP Server, và từng instance liên quan những CVE nào? Nhóm theo device và version. |
| Q070 | {CVE_APACHE_1} ảnh hưởng đến những instance Apache HTTP Server nào trong mạng? Nêu version và source cho từng kết luận. |
| Q071 | Trong mạng, những instance nào chạy BIND 9, và từng instance liên quan những CVE nào? Nhóm theo device và version. |
| Q072 | {CVE_BIND_1} ảnh hưởng đến những instance BIND 9 nào trong mạng? Nêu version và source cho từng kết luận. |
| Q073 | Trong mạng, những instance nào chạy OpenVPN, và từng instance liên quan những CVE nào? Nhóm theo device và version. |
| Q074 | {CVE_OPENVPN_1} ảnh hưởng đến những instance OpenVPN nào trong mạng? Nêu version và source cho từng kết luận. |
| Q075 | Trong mạng, những instance nào chạy OpenSSH Portable, và từng instance liên quan những CVE nào? Nhóm theo device và version. |
| Q076 | {CVE_OPENSSH_1} ảnh hưởng đến những instance OpenSSH Portable nào trong mạng? Nêu version và source cho từng kết luận. |
| Q077 | Trong mạng, những instance nào chạy HAProxy, và từng instance liên quan những CVE nào? Nhóm theo device và version. |
| Q078 | {CVE_HAPROXY_1} ảnh hưởng đến những instance HAProxy nào trong mạng? Nêu version và source cho từng kết luận. |
| Q079 | Trong mạng, những instance nào chạy dnsmasq, và từng instance liên quan những CVE nào? Nhóm theo device và version. |
| Q080 | {CVE_DNSMASQ_1} ảnh hưởng đến những instance dnsmasq nào trong mạng? Nêu version và source cho từng kết luận. |

## F. Tổng hợp nhiều device và kiểm tra scope — 20 câu

| ID | Câu hỏi |
| --- | --- |
| Q081 | Liệt kê các CVE áp dụng trên toàn hệ thống mạng, nhóm theo device, software và version. |
| Q082 | Hai router FRR-A và FRR-B liên quan những CVE nào? Báo kết quả riêng cho từng router. |
| Q083 | Nhóm Web Server chạy nginx và Apache có những CVE áp dụng nào? Tách theo từng instance và software. |
| Q084 | Nhóm Reverse Proxy/Load Balancer chạy nginx và HAProxy có những CVE áp dụng nào? |
| Q085 | Các DNS instances chạy BIND 9 và dnsmasq có những CVE nào? Phân biệt CVE thuộc software nào. |
| Q086 | Các OpenVPN instances có những CVE nào áp dụng với server/client role hiện tại? |
| Q087 | Các SSH instances đang chạy OpenSSH liên quan những CVE nào? Phân biệt ssh client và sshd khi advisory có yêu cầu. |
| Q088 | CVE nào trong test scope ảnh hưởng đến nhiều hơn một device? Liệt kê device và software tương ứng. |
| Q089 | Những instance nào có ít nhất hai CVE áp dụng trong test scope? Nêu từng CVE và source. |
| Q090 | Có tổng cộng bao nhiêu mục device–software–version–CVE khác nhau trong test scope? Liệt kê các mục đã đếm. |
| Q091 | Những software nào có CVE áp dụng trên ít nhất hai instance của chính software đó? |
| Q092 | Có CVE ID nào trong test scope áp dụng cho nhiều software khác nhau trong mạng không? Chỉ liệt kê trường hợp có source hỗ trợ. |
| Q093 | Chỉ báo CVE thuộc nhóm Routing và DNS, nhóm theo router hoặc DNS instance tương ứng. |
| Q094 | Chỉ kiểm tra NGINX-A, APACHE-A, BIND-A và HAPROXY-A: mỗi instance có những CVE nào áp dụng? |
| Q095 | {CVE_APACHE_1} có ảnh hưởng đến NGINX-A hoặc NGINX-B không? Xác định software mà advisory nói đến trước khi kết luận. |
| Q096 | {CVE_FRR_1} có ảnh hưởng đến OPENSSH-A hoặc OPENSSH-B không? Đối chiếu đúng product và source. |
| Q097 | {CVE_NEGATIVE} có ảnh hưởng đến bất kỳ software/version nào đang cài trong mạng không? |
| Q098 | Trong test scope, có instance nào không bị các CVE đã chọn ảnh hưởng không? Nêu kết luận theo version/configuration và source. |
| Q099 | Tổng hợp source evidence cho các CVE áp dụng trên nhóm Web/Proxy; gắn từng source với đúng instance và software. |
| Q100 | Chỉ xét {CVE_FRR_1}, {CVE_BIND_1}, {CVE_NGINX_1} và {CVE_OPENVPN_1}: liệt kê device/software/version bị ảnh hưởng trong mạng. |
