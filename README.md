# CryptoStack_HashSign - AUTOSAR Crypto Stack Demo

## Tổng Quan

Project minh họa **Crypto Stack** theo kiến trúc **AUTOSAR Classic**, bao gồm:

- **SHA-256**: Thuật toán hash theo FIPS 180-4
- **ECDSA P-256**: Chữ ký số với curve NIST P-256 (secp256r1)

## Kiến Trúc

```
┌─────────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                             │
│                      (main.c)                                    │
│   ┌─────────────────┐              ┌───────────────────────┐    │
│   │  Hash Example   │              │  Sign/Verify Example  │    │
│   └────────┬────────┘              └───────────┬───────────┘    │
├────────────┼───────────────────────────────────┼────────────────┤
│            │    CRYPTO SERVICE MANAGER (CSM)   │                │
│            │           Csm.h / Csm.c           │                │
│   ┌────────▼────────┐              ┌───────────▼───────────┐    │
│   │   Csm_Hash()    │              │ Csm_SignatureGenerate │    │
│   │                 │              │ Csm_SignatureVerify   │    │
│   └────────┬────────┘              └───────────┬───────────┘    │
├────────────┼───────────────────────────────────┼────────────────┤
│            │    CRYPTO INTERFACE (CryIf)       │                │
│            │        CryIf.h / CryIf.c          │                │
│            │      CryIf_ProcessJob()           │                │
├────────────┼───────────────────────────────────┼────────────────┤
│            │       CRYPTO DRIVER               │                │
│   ┌────────▼────────┐              ┌───────────▼───────────┐    │
│   │ Crypto_SHA256.c │              │   Crypto_ECDSA.c      │    │
│   │  (FIPS 180-4)   │              │   (micro-ecc lib)     │    │
│   └─────────────────┘              └───────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Files Trong Project

```
CryptoStack_HashSign/
├── include/
│   ├── Std_Types.h        # AUTOSAR standard types
│   ├── Crypto_Types.h     # Crypto enums, structures
│   ├── Crypto_SHA256.h    # SHA-256 API
│   ├── Crypto_ECDSA.h     # ECDSA API
│   ├── CryIf.h            # Crypto Interface
│   └── Csm.h              # Crypto Service Manager
├── src/
│   ├── Crypto_SHA256.c    # SHA-256 implementation
│   ├── Crypto_ECDSA.c     # ECDSA implementation
│   ├── CryIf.c            # Job routing
│   └── Csm.c              # Service management
├── lib/
│   └── micro-ecc/         # ECC library
├── main.c                 # Demo application
├── Makefile
└── README.md
```

## Build & Run

### Yêu cầu

- GCC (hoặc Clang)
- macOS / Linux / Windows (với MinGW)

### Build

```bash
cd CryptoStack_HashSign
make
```

### Chạy Demo

```bash
./crypto_demo
```

hoặc:

```bash
make run
```

### Clean

```bash
make clean
```

## Các Ví Dụ Trong Demo

### 1. SHA-256 Single Call

Hash chuỗi "abc" và so sánh với FIPS 180-4 test vector.

```c
Csm_Hash(JOB_ID_HASH_SHA256, CRYPTO_OPERATIONMODE_SINGLECALL,
         data, dataLen, digest, &digestLen);
```

### 2. SHA-256 Streaming

Hash dữ liệu lớn theo chunks (mô phỏng firmware verification).

```c
Csm_Hash(jobId, CRYPTO_OPERATIONMODE_START, NULL, 0, NULL, NULL);
Csm_Hash(jobId, CRYPTO_OPERATIONMODE_UPDATE, chunk1, len1, NULL, NULL);
Csm_Hash(jobId, CRYPTO_OPERATIONMODE_UPDATE, chunk2, len2, NULL, NULL);
Csm_Hash(jobId, CRYPTO_OPERATIONMODE_FINISH, chunk3, len3, digest, &digestLen);
```

### 3. ECDSA Sign & Verify

Tạo key pair, ký message, xác thực signature, phát hiện tampering.

```c
// Tạo key pair
Crypto_ECDSA_GenerateKeyPair(&keyPair);

// Set keys
Csm_KeyElementSet_PrivateKey(KEY_SLOT_SIGN, keyPair.privateKey, 32);
Csm_KeyElementSet_PublicKey(KEY_SLOT_VERIFY, keyPair.publicKeyX, keyPair.publicKeyY, 32);

// Sign
Csm_SignatureGenerate(JOB_ID_SIGN, CRYPTO_OPERATIONMODE_SINGLECALL,
                      message, msgLen, signature, &sigLen);

// Verify
Csm_SignatureVerify(JOB_ID_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL,
                    message, msgLen, signature, sigLen, &verifyResult);
```

## API Reference

### CSM Layer (Application gọi trực tiếp)

| Function                         | Mô tả                 |
| -------------------------------- | --------------------- |
| `Csm_Init()`                     | Khởi tạo Crypto Stack |
| `Csm_Hash()`                     | Tính hash (SHA-256)   |
| `Csm_SignatureGenerate()`        | Tạo chữ ký số         |
| `Csm_SignatureVerify()`          | Xác thực chữ ký       |
| `Csm_KeyElementSet_PrivateKey()` | Set ECDSA private key |
| `Csm_KeyElementSet_PublicKey()`  | Set ECDSA public key  |

### Crypto Driver Layer (Low-level)

| Function                         | Mô tả                  |
| -------------------------------- | ---------------------- |
| `Crypto_SHA256_Init()`           | Khởi tạo hash context  |
| `Crypto_SHA256_Update()`         | Thêm data vào hash     |
| `Crypto_SHA256_Finish()`         | Kết thúc và lấy digest |
| `Crypto_SHA256_Calculate()`      | Hash single call       |
| `Crypto_ECDSA_GenerateKeyPair()` | Tạo Private/Public key |
| `Crypto_ECDSA_Sign()`            | Ký digest              |
| `Crypto_ECDSA_Verify()`          | Verify signature       |

## Test Vectors

### SHA-256 (FIPS 180-4)

| Input        | Expected Digest                                                    |
| ------------ | ------------------------------------------------------------------ |
| `"abc"`      | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| `""` (empty) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

### ECDSA P-256

- Key size: 32 bytes (256 bits)
- Signature size: 64 bytes (R: 32 + S: 32)
- Public key: 64 bytes (X: 32 + Y: 32)

## License

MIT License - HALA Academy

## Tham Khảo

- FIPS 180-4: Secure Hash Standard
- FIPS 186-4: Digital Signature Standard (ECDSA)
- AUTOSAR Classic Platform - Crypto Stack
- micro-ecc: https://github.com/kmackay/micro-ecc
