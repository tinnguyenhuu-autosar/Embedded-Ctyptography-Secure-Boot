# Examples - Crypto Stack

Thư mục này chứa các ví dụ chi tiết minh họa cách sử dụng SHA-256 và ECDSA.

## Danh sách Examples

| File                             | Mô tả                                                       |
| -------------------------------- | ----------------------------------------------------------- |
| `example_01_sha256_basic.c`      | SHA-256 cơ bản: hash string, binary, FIPS test vectors      |
| `example_02_sha256_streaming.c`  | SHA-256 streaming: hash firmware theo chunks                |
| `example_03_ecdsa_keygen.c`      | ECDSA key generation: tạo, export, import keys              |
| `example_04_ecdsa_sign_verify.c` | ECDSA sign & verify: quy trình ký và xác thực               |
| `example_05_secure_boot.c`       | Secure Boot simulation: OEM provisioning, signing, ECU boot |

## Build & Run

### Build tất cả

```bash
cd examples
make
```

### Chạy từng example

```bash
./example_01    # SHA-256 Basic
./example_02    # SHA-256 Streaming
./example_03    # ECDSA Key Generation
./example_04    # ECDSA Sign & Verify
./example_05    # Secure Boot Simulation
```

### Chạy tất cả

```bash
make run_all
```

## Chi tiết Examples

### Example 1: SHA-256 Basic

Minh họa các chức năng cơ bản của SHA-256:

- Hash chuỗi ngắn với FIPS 180-4 test vector
- Hash chuỗi rỗng (edge case)
- Hash chuỗi dài (multi-block)
- Hash binary data
- Avalanche effect (1 bit thay đổi → 50% output thay đổi)

**Kiến thức học được:**

- SHA-256 luôn output 32 bytes
- Không thể suy ngược input từ output
- Mọi thay đổi nhỏ đều làm hash thay đổi hoàn toàn

---

### Example 2: SHA-256 Streaming

Minh họa streaming mode cho dữ liệu lớn:

- Init → Update (nhiều lần) → Finish
- Mô phỏng firmware verification
- Phát hiện firmware corrupt

**Kiến thức học được:**

- Streaming mode cho phép hash data lớn hơn RAM
- Context lưu trạng thái giữa các Update
- Quan trọng cho Secure Boot trong ECU

---

### Example 3: ECDSA Key Generation

Minh họa quản lý key:

- Tạo key pair (private + public)
- Giải thích ý nghĩa từng thành phần
- Export key sang hex format
- Import key từ hex
- Key storage best practices

**Kiến thức học được:**

- Private key = số ngẫu nhiên (phải bảo mật)
- Public key = point trên elliptic curve
- Key size: 32 bytes (nhỏ hơn RSA nhiều)

---

### Example 4: ECDSA Sign & Verify

Minh họa quy trình chữ ký số:

- Quy trình ký chi tiết (từng bước algorithm)
- Quy trình verify chi tiết
- Phát hiện message bị sửa đổi
- Phát hiện signature giả mạo

**Kiến thức học được:**

- ECDSA ký trên hash, không phải message gốc
- Signature khác nhau mỗi lần ký (do random k)
- Verify cần public key (không cần private key)

---

### Example 5: Secure Boot Simulation

Mô phỏng quy trình Secure Boot hoàn chỉnh:

**Phase 1: OEM Manufacturing**

- Tạo master key pair
- Provision ECU với public key vào OTP

**Phase 2: OEM Firmware Development**

- Compile firmware
- Ký bằng private key

**Phase 3: ECU Secure Boot**

- Load trusted key từ OTP
- Hash firmware (streaming)
- Verify signature
- Boot nếu valid

**Phase 4: Attack Simulation**

- Attack 1: Sửa firmware giữ signature → DETECTED
- Attack 2: Ký bằng attacker's key → DETECTED

**Kiến thức học được:**

- Chain of Trust concept
- Tại sao cần OTP cho trusted key
- Tại sao private key phải ở HSM
- Các loại attack và cách phòng chống

## Cấu trúc Output

Mỗi example được thiết kế với:

- `[BƯỚC X]` markers cho từng bước
- Giải thích chi tiết bằng tiếng Việt
- Hiển thị hex values cho data/hash/signature
- Status indicators: ✓ (pass) / ✗ (fail)
- Unicode boxes cho kết quả quan trọng
