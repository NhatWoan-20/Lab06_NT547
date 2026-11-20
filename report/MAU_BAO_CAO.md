# NT547 - LAB 06 - BÁO CÁO (TỰ ĐIỀN)

**MSSV:** 22521203  | **Họ tên:** Nguyễn Nhật Quang | **Lớp:** NT547.R11.ANTT
**Session code tự sinh:** SC-A99CC0 | **Tên contract:** TipJar_1203
**Solidity / Slither:** 0.8.24 / 0.11.6 | **Ngày hoàn thành:** 20/11/2026
**URL GitHub repository:** https://github.com/NhatWoan-20/Lab06_NT547

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
- 3 detector **khác tên**: `reentrancy-eth`, `arbitrary-send-eth`, `controlled-delegatecall`.

| ID finding | Detector | Impact | Confidence | Source (file:hàm:dòng) | Luồng dữ liệu: đầu vào -> thao tác -> tác hại |
|---|---|---|---|---|---|
| F01 | `reentrancy-eth` | High | Medium | `AuditTarget.sol:TipJar_1203.withdraw():59-65` (call: `62`, state write: `64`) | Người gọi có số dư `deposits[msg.sender] > 0` gọi `withdraw()` -> Hợp đồng chuyển ETH ra ngoài qua `msg.sender.call{value: amount}("")` (dòng 62) **trước khi** cập nhật trạng thái `deposits[msg.sender] = 0` (dòng 64) -> Hợp đồng nhận tiền của kẻ tấn công kích hoạt `receive()`/`fallback()` gọi đệ quy lại `withdraw()` nhiều lần liên tiếp khi số dư chưa bị trừ, rút cạn toàn bộ quỹ ETH của hợp đồng. |
| F02 | `arbitrary-send-eth` | High | Medium | `AuditTarget.sol:TipJar_1203.grant(address,uint256):55-57` (transfer: `56`) | Bất kỳ địa chỉ nào truyền tham số người nhận `to` và số lượng `amount` vào hàm `external grant()` -> Hàm không kiểm tra quyền truy cập (`onlyOwner`) và không kiểm tra/khấu trừ số dư của người gọi mà thực thi trực tiếp `to.transfer(amount)` (dòng 56) -> Kẻ tấn công không có quyền vẫn có thể rút trái phép toàn bộ ETH của hợp đồng về địa chỉ tùy ý. |
| F03 | `controlled-delegatecall` | High | Medium | `AuditTarget.sol:TipJar_1203.proxyCall(address,bytes):67-70` (delegatecall: `68`) | Người gọi bất kỳ truyền địa chỉ hợp đồng đích `target` và dữ liệu `data` tự chọn vào hàm `external proxyCall()` -> Hàm không giới hạn quyền gọi và không xác thực địa chỉ đích mà thực thi trực tiếp `target.delegatecall(data)` (dòng 68) ngay trên ngữ cảnh bộ nhớ (storage) của `TipJar_1203` -> Kẻ tấn công chạy mã độc từ hợp đồng `target` để ghi đè slot 0 (`owner`), chiếm toàn quyền điều khiển hợp đồng. |

## 2. Triage và sửa lỗi (2,5 điểm)

Đọc toàn bộ AuditTarget.sol: nhận diện **4 mẫu lỗi thật + 2 đoạn cần đánh giá ngữ cảnh**,
kể cả khi Slither không hiển thị đủ 6 cảnh báo. Với mẫu không có detector,
ghi “Manual review / Not reported”, KHÔNG sửa slither.json hoặc tạo finding giả.

| Detector + vị trí | TP / FP / Chưa kết luận | Bằng chứng kiểm soát/khả năng khai thác | Biện pháp (Fix / Accept có lý do) | Sau sửa |
|---|---|---|---|---|
| `arbitrary-send-eth` (High) — `TipJar_1203.grant()` (`AuditTarget.sol:55-57`) | **TP** | Đường gọi `external`, không kiểm tra quyền (`onlyOwner`) và không trừ số dư state của người gọi mà chuyển trực tiếp `to.transfer(amount)` (dòng 56). Bất kỳ ai cũng gọi được để rút ETH của contract. | **Fix**: Thêm modifier `onlyOwner` và kiểm tra `require(to != address(0), "zero")` (dòng 57-60). | Đã khắc phục (`0` finding) |
| `controlled-delegatecall` (High) — `TipJar_1203.proxyCall()` (`AuditTarget.sol:67-70`) | **TP** | Đường gọi `external`, không giới hạn quyền, thực thi `target.delegatecall(data)` (dòng 68) với `target` và `data` do người gọi truyền vào, cho phép ghi đè biến state `owner` ở slot 0. | **Fix**: Thêm modifier `onlyOwner`, kiểm tra `require(target != address(0), "zero")` và đổi `delegatecall` sang `target.call(data)` (dòng 70-74). | Đã khắc phục (`0` finding) |
| `reentrancy-eth` (High) — `TipJar_1203.withdraw()` (`AuditTarget.sol:59-65`) | **TP** | Đường gọi `external` không có mutex; gọi ngoài `msg.sender.call{value: amount}("")` (dòng 62) trước khi cập nhật state `deposits[msg.sender] = 0` (dòng 64), cho phép gọi đệ quy rút cạn ETH. | **Fix**: Áp dụng *Checks-Effects-Interactions (CEI)* — đặt `deposits[msg.sender] = 0` trước khi gọi `.call` (dòng 62-68). | Đã khắc phục (`0` finding) |
| `tx-origin` (Medium) — `TipJar_1203.setAdmin()` (`AuditTarget.sol:72-76`) | **TP** | Đường gọi `external` kiểm tra quyền bằng `require(tx.origin == owner)` (dòng 73) rồi cập nhật state `owner = newOwner` (dòng 75); dễ bị tấn công phishing qua hợp đồng trung gian. | **Fix**: Thay bằng modifier `onlyOwner` (`require(msg.sender == owner)`) và emit sự kiện `OwnerChanged` (dòng 76-80). | Đã khắc phục (`0` finding) |
| `reentrancy-eth` (High) — `TipJar_1203.exitSafe()` (`AuditTarget.sol:48-53`) | **Accepted (FP theo ngữ cảnh)** | Đường gọi `external` có cập nhật `safeBalances[msg.sender] = 0` (dòng 52) sau `.call` (dòng 50), nhưng đã được khoá bởi modifier mutex `exclusive` (`require(!locked)`), không thể tái nhập. | **Fix làm sạch cảnh báo**: Chuyển `safeBalances[msg.sender] = 0` lên trước `.call` theo chuẩn CEI và thêm `require(a > 0, "empty")` (dòng 49-55). | Đã làm sạch cảnh báo (`0` finding) |
| `incorrect-equality` (Medium) — `TipJar_1203.noFunds()` (`AuditTarget.sol:78-80`) | **Accepted (FP theo ngữ cảnh)** | Đường gọi `external view`, không cập nhật state; phép so sánh `address(this).balance == 0` (dòng 79) chỉ trả về `bool` để hiển thị, không khoá logic rút tiền. | **Accept & Suppress**: Giữ nguyên hàm `view` và đặt `// slither-disable-next-line incorrect-equality` ngay trước dòng 84. | Đã suppress có kiểm soát (`0` finding) |

- Mô tả ít nhất 01 kịch bản khai thác TP: người gọi -> điều kiện -> call/state -> hậu quả:
  - **Khai thác `reentrancy-eth` tại `withdraw()`**: Attacker dùng hợp đồng có `receive() external payable` gọi `stake()` nạp `1 ETH` (thoả điều kiện `deposits[msg.sender] > 0`) -> Gọi `withdraw()`, hợp đồng thực hiện `msg.sender.call{value: amount}("")` (dòng 62) trước khi cập nhật state `deposits[msg.sender] = 0` (dòng 64) -> `receive()` của Attacker kích hoạt gọi đệ quy lại `withdraw()` liên tiếp khi số dư chưa bị trừ về 0 -> Rút cạn toàn bộ ETH của hợp đồng `TipJar_1203`.
- Phân tích 01 finding có severity cao nhưng risk thực tế không tương ứng:
  - **Finding `reentrancy-eth` (High) tại `exitSafe()` (`AuditTarget.sol:48-53`)**: Slither báo mức **High** vì thấy biến trạng thái `safeBalances[msg.sender] = 0` được ghi sau lệnh gọi ngoài `msg.sender.call{value: a}("")`. Tuy nhiên **risk thực tế bằng 0** vì cả hai hàm `depositSafe()` và `exitSafe()` đều gắn modifier mutex `exclusive` (`require(!locked, "reentrant"); locked = true; _; locked = false;`), mọi lệnh gọi đệ quy trong cùng giao dịch đều bị `revert` ngay lập tức. Việc chuyển dòng cập nhật state lên trước `.call` được thực hiện nhằm tuân thủ chuẩn CEI và giúp tool không còn báo cảnh báo trên CI.
- Dẫn bằng chứng `git diff`, scan before/after và giải thích cảnh báo còn lại:
  - **So sánh kết quả quét Before vs After**:
    - `before_raw`: **13 findings** (`4 High, 2 Medium, 2 Low, 5 Informational`) -> `after_raw`: **5 findings** (`0 High, 0 Medium, 0 Low, 5 Informational`).
    - `before_configured`: **6 findings** (`4 High, 2 Medium`) -> `after_configured`: **0 findings** (`0 High, 0 Medium, 0 Low, 0 Informational`).
  - **Tóm tắt thay đổi mã nguồn (`git diff c0450e3 e8012f8 -- AuditTarget.sol`)**:
    - `exitSafe()` & `withdraw()`: Đưa lệnh gán `safeBalances[msg.sender] = 0` và `deposits[msg.sender] = 0` lên trước `.call{value: ...}("")` (và kiểm tra số dư `> 0`).
    - `grant()`: Thêm modifier `onlyOwner` và `require(to != address(0), "zero")`.
    - `proxyCall()`: Thêm modifier `onlyOwner`, `require(target != address(0), "zero")` và thay `target.delegatecall(data)` bằng `target.call(data)`.
    - `setAdmin()`: Thay `require(tx.origin == owner)` bằng modifier `onlyOwner` và thêm `emit OwnerChanged(owner, newOwner)`.
    - `noFunds()`: Thêm `// slither-disable-next-line incorrect-equality` ngay trên dòng `return address(this).balance == 0;`.
  - **Giải thích cảnh báo còn lại**: Bản `after_raw` chỉ còn 5 cảnh báo mức `Informational` (4 `low-level-calls` do dùng `.call` chuẩn Solidity và 1 `naming-convention` do tên contract `TipJar_1203` chứa dấu gạch dưới theo MSSV), không ảnh hưởng đến an toàn của hợp đồng.
- Lý do của mọi `slither-disable-next-line`:
  - Đặt duy nhất `// slither-disable-next-line incorrect-equality` tại dòng 83 (ngay trước `return address(this).balance == 0;` trong hàm `noFunds()`).
  - **Lý do & kiểm soát bù trừ**: Hàm `noFunds()` là hàm `external view` chỉ phục vụ truy vấn hiển thị trạng thái, không được gọi trong bất kỳ câu lệnh `require` hay điều kiện rút tiền/thay đổi state nào, nên việc số dư contract bị ép tăng wei từ bên ngoài không gây rủi ro DoS hay khoá quỹ.

## 3. Kiến trúc / Inheritance (1,5 điểm)

- Lệnh printer đã chạy:
  - `python tools/print_arch.py` (thực thi `slither contracts/ArchitectureDemo.sol --print human-summary` và `slither contracts/ArchitectureDemo.sol --print inheritance-graph`)
  - Render đồ thị PNG với Graphviz: `dot -Tpng evidence/architecture/ArchitectureDemo.sol.dot -o evidence/architecture/inheritance.png`
- Ảnh `evidence/architecture/inheritance.png` (hoặc .dot, nếu Graphviz chưa có):
  - Đã xuất thành công `evidence/architecture/human_summary.txt` (ghi nhận 3 contracts, 23 SLOC, `StudentAsset` có 4 functions tổng hợp), `evidence/architecture/ArchitectureDemo.sol.dot` (`ArchitectureDemo.sol.inheritance-graph.dot`) và ảnh sơ đồ kế thừa `evidence/architecture/inheritance.png`.
  - Cấu trúc đồ thị kế thừa trong `.dot` / `inheritance.png`:
    - `c97_StudentAsset -> c25_AccessManaged [ label="1" ]`
    - `c97_StudentAsset -> c56_BalanceLedger [ label="2" ]`
- Access control nằm ở **`AccessManaged`** (`contracts/ArchitectureDemo.sol:5-9`, lưu biến trạng thái `address public admin` và định nghĩa `modifier onlyAdmin()`); logic số dư nằm ở **`BalanceLedger`** (`contracts/ArchitectureDemo.sol:10-18`, quản lý `mapping(address => uint256) internal balances`, hàm đọc `balanceOf(address)` và hàm nội bộ `_credit(address, uint256)`); contract triển khai nằm ở **`StudentAsset`** (`contracts/ArchitectureDemo.sol:19-26`, kế thừa `AccessManaged, BalanceLedger` và cung cấp hàm gọi từ bên ngoài `mint(address to, uint256 amount) external onlyAdmin`).
- Giải thích 3–5 câu điểm audit cần bắt đầu:
  - Khi audit hệ thống hợp đồng có kế thừa đa cấp, auditor nên **bắt đầu từ contract triển khai thực tế là `StudentAsset` tại hàm entrypoint `mint(address to, uint256 amount) external onlyAdmin`**, vì đây là bề mặt giao tiếp duy nhất từ bên ngoài có khả năng làm thay đổi trạng thái hệ thống (còn `balanceOf` chỉ là hàm `external view`).
  - Từ entrypoint `mint()`, auditor lần ngược theo đồ thị kế thừa lên **contract cha thứ nhất là `AccessManaged`** để kiểm tra logic bảo mật trọng yếu (security-critical) về phân quyền: biến `admin` được khởi tạo trong `constructor()` ra sao, có hàm nào cho phép chiếm quyền `admin` không, và modifier `onlyAdmin()` có kiểm tra đúng `msg.sender == admin` trước khi chạy `_;` hay không.
  - Tiếp theo, auditor kiểm tra **contract cha thứ hai là `BalanceLedger`** nơi chứa logic security-critical về tài sản (`mapping balances` có phạm vi `internal` và hàm `_credit()` chỉ được phép gọi nội bộ sau khi đã qua kiểm tra `require(to != address(0), "zero")` tại `mint()`).
  - Quy trình audit đi từ **Entrypoint (`StudentAsset.mint`) -> Kiểm soát quyền (`AccessManaged.onlyAdmin`) -> Biến đổi trạng thái cốt lõi (`BalanceLedger._credit`)** giúp bao phủ trọn vẹn luồng dữ liệu từ đầu vào của người gọi đến biến lưu trữ số dư.

## 4. Red -> Green CI (2,5 điểm)

| Phase | Commit (full/short SHA) | Run URL | Kết quả | Detector khiến RED / lý do GREEN |
|---|---|---|---|---|
| Baseline vulnerable | `c0450e3d12136751bc23eff953b61112c4532d09` (`c0450e3`) | https://github.com/NhatWoan-20/Lab06_NT547/actions/runs/44766819209/job/136393527892 | RED | Slither phát hiện 4 lỗi **High** (`arbitrary-send-eth` tại `grant`, `controlled-delegatecall` tại `proxyCall`, `reentrancy-eth` tại `withdraw` và `exitSafe`) và 2 lỗi **Medium** (`incorrect-equality` tại `noFunds`, `tx-origin` tại `setAdmin`), vượt ngưỡng `fail-on: medium` của workflow. |
| Patched | `e8012f8f40232fc5729850c4f523b9f0d5737c93` (`e8012f8`) | https://github.com/NhatWoan-20/Lab06_NT547/actions/runs/44769462489 | GREEN | Toàn bộ 4 lỗi **TP** (`withdraw`, `grant`, `proxyCall`, `setAdmin`) và lỗi ngữ cảnh `exitSafe` đã được sửa triệt để trong mã nguồn; hàm `noFunds()` (`view`) được đánh dấu `slither-disable-next-line incorrect-equality` có giải thích. Số lượng finding High/Medium giảm về `0`, thoả ngưỡng `fail-on: medium`. |

- So sánh local `--fail-none` (thu thập findings) với CI `fail-on: medium`:
  - Tại **local**, script `tools/scan.py` gọi Slither với cờ `--fail-none` để tiến trình luôn kết thúc với `exit code = 0` ngay cả khi hợp đồng có lỗ hổng bảo mật; mục đích là để chương trình không bị ngắt giữa chừng và luôn xuất đủ bộ file bằng chứng (`slither.json`, `findings.csv`, `summary.json`, `command_and_output.txt`) phục vụ quá trình phân tích/triage.
  - Trên **GitHub Actions CI**, workflow `.github/workflows/slither.yml` đặt `fail-on: medium` đóng vai trò **Quality Gate (cổng kiểm soát chất lượng)**: bất kỳ phát hiện nào có mức độ từ `Medium` hoặc `High` trở lên chưa được khắc phục (hoặc chưa được chấp nhận có kiểm soát) sẽ khiến Slither trả về mã lỗi khác `0` và làm toàn bộ pipeline CI bị đánh **RED (Failed)**, ngăn chặn mã lỗi được hợp nhất.
- `exclude_low/informational` thay đổi kết quả hiển thị ra sao:
  - Khi cấu hình `"exclude_low": true` và `"exclude_informational": true` trong `slither.config.json`, Slither bỏ qua các cảnh báo mức thấp (`missing-zero-check`) và thông tin (`low-level-calls`, `naming-convention`), làm giảm tổng số kết quả hiển thị từ **13 findings** (ở chế độ `raw`) xuống còn **6 findings** (ở chế độ `configured` trước khi sửa). Nhờ vậy, lập trình viên và CI pipeline tập trung hoàn toàn vào các rủi ro thực sự nghiêm trọng (`High` và `Medium`) mà không bị nhiễu bởi các cảnh báo phong cách mã nguồn.

## 5. Mutation RED -> GREEN (1,5 điểm)

- Mutation một dòng: `require(msg.sender == owner, "not owner")` -> `require(tx.origin == owner, "not owner")` trong `modifier onlyOwner` (và tại hàm kiểm tra quyền `setAdmin`).
- Detector kỳ vọng: `tx-origin` (mức Medium); xác nhận của em từ CI:
  - Khi chỉ sửa dòng `require(tx.origin == owner, "not owner")` bên trong `modifier onlyOwner` (commit `648ea3313356359ec44af832db9dcc93f6271697`, Run URL: https://github.com/NhatWoan-20/Lab06_NT547/actions/runs/44772390348), Slither `0.11.6` bỏ sót (False Negative) vì hàm `detect_tx_origin()` trong `slither/detectors/statements/tx_origin.py` chỉ duyệt qua `contract.functions` mà không duyệt qua `contract.modifiers`.
  - Khi đặt dòng `require(tx.origin == owner, "not owner")` vào hàm `setAdmin` (commit `ae5d48db7fd88c8ec566e25aa6afa96e44a4b3f9`), GitHub Actions CI xác nhận chính xác **`Detector: tx-origin` (Impact: Medium, Confidence: Medium)** tại `TipJar_1203.setAdmin(address)` và đánh **RED (Failed)** đúng ngưỡng `fail-on: medium`.
  - Sau khi revert mutation (commit `90e2ae92dff61c058b1780c0a215c94dd8f22afa`), Slither xác nhận `0 result(s) found` và pipeline CI quay trở lại trạng thái **GREEN**.

| Phase | Commit SHA | Run URL | Kết quả |
|---|---|---|---|
| Mutation | `ae5d48db7fd88c8ec566e25aa6afa96e44a4b3f9` (`ae5d48d`) *(Modifier test: `648ea33`)* | https://github.com/NhatWoan-20/Lab06_NT547/actions/runs/44775552172 *(Modifier run: https://github.com/NhatWoan-20/Lab06_NT547/actions/runs/44772390348)* | RED |
| Revert mutation | `90e2ae92dff61c058b1780c0a215c94dd8f22afa` (`90e2ae9`) | https://github.com/NhatWoan-20/Lab06_NT547/actions/runs/44775929633 | GREEN |

- Giải thích sự thay đổi về nguồn định danh/authorization:
  - `msg.sender` định danh **người gọi trực tiếp (immediate caller)** của lệnh gọi hàm hiện tại (có thể là tài khoản người dùng EOA hoặc một hợp đồng thông minh khác), trong khi `tx.origin` luôn trả về **tài khoản EOA khởi tạo giao dịch ban đầu** xuyên suốt toàn bộ chuỗi gọi (call chain).
  - Khi đổi từ `msg.sender == owner` sang `tx.origin == owner`, cơ chế phân quyền bị suy yếu nghiêm trọng: nếu chủ sở hữu hợp pháp (`owner`) bị dụ tương tác với một hợp đồng độc hại trung gian (ví dụ gọi hàm nhận thưởng/airdrop giả mạo), hợp đồng độc hại đó có thể gọi tiếp sang hàm quản trị của `TipJar_1203`. Lúc này `msg.sender` là địa chỉ hợp đồng độc hại nhưng `tx.origin` vẫn chính là `owner`, khiến điều kiện `require(tx.origin == owner)` bị vượt qua và kẻ tấn công thực thi được các thao tác đặc quyền của chủ sở hữu.

## 6. Bằng chứng, tự kiểm

- [x] `AuditTarget.sol`, `lab_identity.json`
- [x] `evidence/before_raw/` và `evidence/before_configured/`
- [x] `evidence/after_raw/` và `evidence/after_configured/`
- [x] `evidence/architecture/`
- [x] 04 URL Actions run RED/GREEN/RED/GREEN + 04 commit SHA
- [x] Link repo và ảnh màn hình có terminal / URL / commit SHA; không cắt mất ngữ cảnh
- [x] Các finding được triage, không chép lại mô tả detector thay cho suy luận
- [x] Tuyệt đối không có seed phrase, private key, credentials

**Nhận xét cuối cùng (5–7 câu):**
