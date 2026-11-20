# NT547 - LAB 06 - BÁO CÁO (TỰ ĐIỀN)

**MSSV:** 22521203  | **Họ tên:** Nguyễn Nhật Quang | **Lớp:** NT547.R11.ANTT
**Session code tự sinh:** SC-A99CC0 | **Tên contract:** TipJar_1203
**Solidity / Slither:** 0.8.24 / 0.11.6 | **Ngày hoàn thành:** 20/11/2026
**URL GitHub repository:** ...

## 1. Static scan (2,0 điểm)

- Lệnh raw: `python tools/scan.py --mode raw --tag before`
- Số lượng finding raw từ `evidence/before_raw/summary.json`:
  - High: **4**; Medium: **2**; Low: **2**; Informational: **5**; Optimization: **0** *(Tổng cộng: **13** findings)*
- Chạy configured: `python tools/scan.py --mode configured --tag before`
  - Số lượng finding configured từ `evidence/before_configured/summary.json`: High: **4**; Medium: **2**; Low: **0**; Informational: **0**; Optimization: **0** *(Tổng cộng: **6** findings)*
- So sánh raw/configured:
  - Chế độ **raw** (dùng `config/slither.raw.json` rỗng `{}`) chạy toàn bộ 102 detectors và xuất ra **13 findings** (bao gồm cả 2 cảnh báo mức `Low` là `missing-zero-check` và 5 cảnh báo mức `Informational` là `low-level-calls`, `naming-convention`).
  - Chế độ **configured** (dùng `slither.config.json` với `"exclude_low": true, "exclude_informational": true, "detectors_to_exclude": "solc-version"`) chạy 64 detectors và lọc bỏ 7 cảnh báo mức `Low`/`Informational`, chỉ giữ lại đúng **6 findings** trọng tâm.
  - **Nhận xét quan trọng**: Toàn bộ **4 lỗi High** và **2 lỗi Medium** đều được giữ nguyên ở cả hai chế độ (**không biến mất High/Medium khi chỉ đổi config**), giúp giảm nhiễu khi đọc báo cáo nhưng vẫn bảo toàn ngưỡng kiểm soát rủi ro bảo mật.
- 3 detector **khác tên** (liệt kê đầy đủ 5 detector High/Medium khác tên phát hiện được trong `findings.csv`): `reentrancy-eth`, `arbitrary-send-eth`, `controlled-delegatecall`, `tx-origin`, `incorrect-equality`.

| ID finding | Detector | Impact | Confidence | Source (file:hàm:dòng) | Luồng dữ liệu: đầu vào -> thao tác -> tác hại |
|---|---|---|---|---|---|
| F01 | `reentrancy-eth` | High | Medium | `AuditTarget.sol:TipJar_1203.withdraw():59-65` (call: `62`, state write: `64`) | Người gọi có số dư `deposits[msg.sender] > 0` gọi `withdraw()` -> Hợp đồng chuyển ETH ra ngoài qua `msg.sender.call{value: amount}("")` (dòng 62) **trước khi** cập nhật trạng thái `deposits[msg.sender] = 0` (dòng 64) -> Hợp đồng nhận tiền của kẻ tấn công kích hoạt `receive()`/`fallback()` gọi đệ quy lại `withdraw()` nhiều lần liên tiếp khi số dư chưa bị trừ, rút cạn toàn bộ quỹ ETH của hợp đồng. |
| F02 | `arbitrary-send-eth` | High | Medium | `AuditTarget.sol:TipJar_1203.grant(address,uint256):55-57` (transfer: `56`) | Bất kỳ địa chỉ nào truyền tham số người nhận `to` và số lượng `amount` vào hàm `external grant()` -> Hàm không kiểm tra quyền truy cập (`onlyOwner`) và không kiểm tra/khấu trừ số dư của người gọi mà thực thi trực tiếp `to.transfer(amount)` (dòng 56) -> Kẻ tấn công không có quyền vẫn có thể rút trái phép toàn bộ ETH của hợp đồng về địa chỉ tùy ý. |
| F03 | `controlled-delegatecall` | High | Medium | `AuditTarget.sol:TipJar_1203.proxyCall(address,bytes):67-70` (delegatecall: `68`) | Người gọi bất kỳ truyền địa chỉ hợp đồng đích `target` và dữ liệu `data` tự chọn vào hàm `external proxyCall()` -> Hàm không giới hạn quyền gọi và không xác thực địa chỉ đích mà thực thi trực tiếp `target.delegatecall(data)` (dòng 68) ngay trên ngữ cảnh bộ nhớ (storage) của `TipJar_1203` -> Kẻ tấn công chạy mã độc từ hợp đồng `target` để ghi đè slot 0 (`owner`), chiếm toàn quyền điều khiển hợp đồng. |
| F04 | `tx-origin` | Medium | Medium | `AuditTarget.sol:TipJar_1203.setAdmin(address):72-76` (check: `73`) | Chủ sở hữu (`owner`) bị dụ gọi vào một hợp đồng trung gian của kẻ tấn công và hợp đồng đó gọi tiếp sang `setAdmin(newOwner)` -> Hàm xác thực danh tính bằng `require(tx.origin == owner)` (dòng 73) thay vì `msg.sender` nên điều kiện kiểm tra vẫn hợp lệ -> Biến trạng thái `owner` bị gán thành địa chỉ `newOwner` của kẻ tấn công (dòng 75), làm chủ sở hữu mất quyền quản trị. |
| F05 | `incorrect-equality` | Medium | High | `AuditTarget.sol:TipJar_1203.noFunds():78-80` (check: `79`) | Người gọi truy vấn hàm `external view noFunds()` -> Hàm kiểm tra số dư hợp đồng bằng phép so sánh bằng tuyệt đối `address(this).balance == 0` (dòng 79) -> Bất kỳ ai cũng có thể cưỡng bức gửi thêm wei vào hợp đồng (qua `selfdestruct` hoặc coinbase) làm kết quả trả về luôn là `false`, tuy nhiên đây chỉ là hàm `view` phục vụ hiển thị nên không làm hỏng trạng thái hay kẹt quỹ. |

## 2. Triage và sửa lỗi (2,5 điểm)

Đọc toàn bộ AuditTarget.sol: nhận diện **4 mẫu lỗi thật + 2 đoạn cần đánh giá ngữ cảnh**,
kể cả khi Slither không hiển thị đủ 6 cảnh báo. Với mẫu không có detector,
ghi “Manual review / Not reported”, KHÔNG sửa slither.json hoặc tạo finding giả.

| Detector + vị trí | TP / FP / Chưa kết luận | Bằng chứng kiểm soát/khả năng khai thác | Biện pháp (Fix / Accept có lý do) | Sau sửa |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |
| | | | | |

- Mô tả ít nhất 01 kịch bản khai thác TP: người gọi -> điều kiện -> call/state -> hậu quả: ...
- Phân tích 01 finding có severity cao nhưng risk thực tế không tương ứng: ...
- Dẫn bằng chứng `git diff`, scan before/after và giải thích cảnh báo còn lại: ...
- Lý do của mọi `slither-disable-next-line`: ... (tên detector, đúng vị trí, kiểm soát bù trừ).

## 3. Kiến trúc / Inheritance (1,5 điểm)

- Lệnh printer đã chạy: ...
- Ảnh `evidence/architecture/inheritance.png` (hoặc .dot, nếu Graphviz chưa có): ...
- Access control nằm ở ...; logic số dư nằm ở ...; contract triển khai nằm ở ...
- Giải thích 3–5 câu điểm audit cần bắt đầu: ...

## 4. Red -> Green CI (2,5 điểm)

| Phase | Commit (full/short SHA) | Run URL | Kết quả | Detector khiến RED / lý do GREEN |
|---|---|---|---|---|
| Baseline vulnerable | | | RED | |
| Patched | | | GREEN | |

- So sánh local `--fail-none` (thu thập findings) với CI `fail-on: medium`: ...
- `exclude_low/informational` thay đổi kết quả hiển thị ra sao: ...

## 5. Mutation RED -> GREEN (1,5 điểm)

- Mutation một dòng: `require(msg.sender == owner, "not owner")` -> `require(tx.origin == owner, "not owner")` trong `modifier onlyOwner`.
- Detector kỳ vọng: `tx-origin` (mức Medium); xác nhận của em từ CI: ...

| Phase | Commit SHA | Run URL | Kết quả |
|---|---|---|---|
| Mutation | | | RED |
| Revert mutation | | | GREEN |

- Giải thích sự thay đổi về nguồn định danh/authorization: ...

## 6. Bằng chứng, tự kiểm

- [ ] `AuditTarget.sol`, `lab_identity.json`
- [ ] `evidence/before_raw/` và `evidence/before_configured/`
- [ ] `evidence/after_raw/` và `evidence/after_configured/`
- [ ] `evidence/architecture/`
- [ ] 04 URL Actions run RED/GREEN/RED/GREEN + 04 commit SHA
- [ ] Link repo và ảnh màn hình có terminal / URL / commit SHA; không cắt mất ngữ cảnh
- [ ] Các finding được triage, không chép lại mô tả detector thay cho suy luận
- [ ] Tuyệt đối không có seed phrase, private key, credentials

**Nhận xét cuối cùng (5–7 câu):** ...
