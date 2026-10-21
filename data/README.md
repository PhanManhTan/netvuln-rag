# Data directories

- `raw/<source>/`: response nguyên bản, chia theo timestamp và page.
- `processed/`: dữ liệu JSONL theo schema chung để tạo chunk và index.

Hai thư mục dữ liệu được bỏ qua bởi Git, ngoại trừ file `.gitkeep`. Không chỉnh sửa raw data bằng tay; nếu cần hỗ trợ nguồn mới, thêm adapter trực tiếp trong `ingestion/`, đăng ký tại `ingestion/registry.py`, rồi tạo lại processed data.

