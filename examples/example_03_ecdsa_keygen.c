/*******************************************************************************
 * @file    example_03_ecdsa_keygen.c
 * @brief   Ví dụ 3: ECDSA Key Generation - Tạo và quản lý Private/Public key
 *
 * @author  HALA Academy
 * @version 1.0.0
 * @date    2026-01-02
 *
 * @note    VÍ DỤ NÀY MINH HỌA:
 *          1. Tạo key pair ECDSA P-256
 *          2. Giải thích ý nghĩa Private/Public key
 *          3. Export key sang hex format
 *          4. Import key từ hex
 *          5. Key storage best practices
 *
 * @compile gcc -o example_03 example_03_ecdsa_keygen.c \
 *              ../src/Crypto_ECDSA.c ../src/Crypto_SHA256.c \
 *              ../lib/micro-ecc/uECC.c \
 *              -I../include -I../lib/micro-ecc -Wall
 * @run     ./example_03
 ******************************************************************************/

#include "Crypto_ECDSA.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*===========================================================================*/
/*                    HELPER FUNCTIONS                                        */
/*===========================================================================*/
static void PrintHex(const char *label, const uint8 *data, uint32 length) {
  printf("%s", label);
  for (uint32 i = 0; i < length; i++) {
    printf("%02x", data[i]);
  }
  printf("\n");
}

static void PrintHexFormatted(const char *label, const uint8 *data,
                              uint32 length) {
  printf("%s\n", label);
  for (uint32 i = 0; i < length; i++) {
    if (i % 16 == 0)
      printf("  ");
    printf("%02x ", data[i]);
    if ((i + 1) % 16 == 0)
      printf("\n");
  }
  if (length % 16 != 0)
    printf("\n");
}

/*===========================================================================*/
/*                    VÍ DỤ 3.1: TẠO KEY PAIR                                 */
/*===========================================================================*/
/**
 * @brief   Tạo key pair ECDSA P-256 và giải thích các thành phần
 *
 * @details ECDSA P-256 (secp256r1) là gì?
 *
 *          ECDSA = Elliptic Curve Digital Signature Algorithm
 *          P-256 = Curve được NIST định nghĩa với:
 *            - p = 2^256 - 2^224 + 2^192 + 2^96 - 1 (modulus)
 *            - n = order of the curve (số lượng điểm trên curve)
 *            - G = generator point (điểm cơ sở)
 *
 *          Key generation:
 *            1. Chọn d ngẫu nhiên trong [1, n-1] → Private key
 *            2. Tính Q = d × G → Public key (point multiplication)
 *
 *          Bảo mật:
 *            - Biết Q không thể tính ngược d (ECDLP problem)
 *            - 256-bit ECC ≈ 3072-bit RSA về độ an toàn
 */
static void Example_GenerateKeyPair(Crypto_ECDSA_KeyPairType *keyPair) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║  VÍ DỤ 3.1: TẠO KEY PAIR ECDSA P-256                         ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");

  printf("\n[KIẾN THỨC NỀN TẢNG]\n");
  printf("  ┌─────────────────────────────────────────────────────────┐\n");
  printf("  │ ELLIPTIC CURVE: y² = x³ + ax + b (mod p)               │\n");
  printf("  │                                                         │\n");
  printf("  │ P-256 parameters (NIST curve):                         │\n");
  printf("  │   - p = 2^256 - 2^224 + 2^192 + 2^96 - 1               │\n");
  printf("  │   - Key size: 256 bits (32 bytes)                      │\n");
  printf("  │   - Security: Tương đương RSA-3072                     │\n");
  printf("  └─────────────────────────────────────────────────────────┘\n");

  printf("\n[QUÁ TRÌNH TẠO KEY]\n\n");

  printf("  BƯỚC 1: Tạo số ngẫu nhiên d (Private Key)\n");
  printf("  ─────────────────────────────────────────\n");
  printf("    - d là số bí mật trong khoảng [1, n-1]\n");
  printf("    - n là order của curve (~2^256)\n");
  printf("    - PHẢI dùng TRNG (True Random Number Generator)\n");
  printf("    - Trong ECU thực: dùng HSM hardware RNG\n");

  printf("\n  BƯỚC 2: Tính Q = d × G (Public Key)\n");
  printf("  ─────────────────────────────────────\n");
  printf("    - G là generator point (cố định, công khai)\n");
  printf("    - × là phép nhân điểm elliptic curve\n");
  printf("    - Q = (Qx, Qy) là điểm kết quả\n");
  printf("    - Không thể tính ngược d từ Q (bài toán ECDLP)\n");

  printf("\n  BƯỚC 3: Gọi API Crypto_ECDSA_GenerateKeyPair()\n");
  printf("  ─────────────────────────────────────────────────\n");

  Std_ReturnType result = Crypto_ECDSA_GenerateKeyPair(keyPair);

  if (result == E_OK) {
    printf("    ✓ Key pair tạo thành công!\n");

    printf("\n[KẾT QUẢ]\n");

    printf("\n  PRIVATE KEY (d) - 32 bytes - GIỮ BÍ MẬT!\n");
    printf("  ════════════════════════════════════════════\n");
    PrintHexFormatted("", keyPair->privateKey, CRYPTO_ECDSA_P256_KEY_SIZE);
    printf("  ⚠ WARNING: KHÔNG ĐƯỢC log, lưu file, hoặc truyền qua mạng!\n");
    printf("  ⚠ Trong ECU thực: lưu trong HSM/Secure Element\n");

    printf("\n  PUBLIC KEY X (Qx) - 32 bytes - Có thể chia sẻ\n");
    printf("  ══════════════════════════════════════════════\n");
    PrintHexFormatted("", keyPair->publicKeyX, CRYPTO_ECDSA_P256_KEY_SIZE);

    printf("\n  PUBLIC KEY Y (Qy) - 32 bytes - Có thể chia sẻ\n");
    printf("  ══════════════════════════════════════════════\n");
    PrintHexFormatted("", keyPair->publicKeyY, CRYPTO_ECDSA_P256_KEY_SIZE);

    printf("\n[TÓM TẮT KÍCH THƯỚC]\n");
    printf("  - Private key:  32 bytes (256 bits)\n");
    printf("  - Public key:   64 bytes (Qx: 32 + Qy: 32)\n");
    printf("  - Signature:    64 bytes (R: 32 + S: 32)\n");
    printf("  → Nhỏ hơn RSA rất nhiều (RSA-3072 key = 384 bytes)\n");

  } else {
    printf("    ✗ Lỗi tạo key pair!\n");
  }
}

/*===========================================================================*/
/*                    VÍ DỤ 3.2: EXPORT KEY SANG HEX                          */
/*===========================================================================*/
/**
 * @brief   Export key sang hex string để lưu trữ hoặc truyền
 */
static void Example_ExportKey(const Crypto_ECDSA_KeyPairType *keyPair) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║  VÍ DỤ 3.2: EXPORT KEY SANG HEX FORMAT                       ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");

  printf("\n[TẠI SAO CẦN EXPORT?]\n");
  printf("  - Backup key (encrypted) để recovery\n");
  printf("  - Chia sẻ public key với đối tác\n");
  printf("  - Nhúng public key vào firmware\n");

  printf("\n[FORMAT PHỔ BIẾN]\n");

  /* 1. Raw hex */
  printf("\n  1. RAW HEX (thường dùng trong embedded)\n");
  printf("  ─────────────────────────────────────────\n");
  PrintHex("     Public Key X: ", keyPair->publicKeyX,
           CRYPTO_ECDSA_P256_KEY_SIZE);
  PrintHex("     Public Key Y: ", keyPair->publicKeyY,
           CRYPTO_ECDSA_P256_KEY_SIZE);

  /* 2. Uncompressed format (04 || X || Y) */
  printf("\n  2. UNCOMPRESSED FORMAT (65 bytes: 04 || X || Y)\n");
  printf("  ────────────────────────────────────────────────\n");
  printf("     04"); /* Prefix byte for uncompressed */
  for (uint32 i = 0; i < CRYPTO_ECDSA_P256_KEY_SIZE; i++) {
    printf("%02x", keyPair->publicKeyX[i]);
  }
  for (uint32 i = 0; i < CRYPTO_ECDSA_P256_KEY_SIZE; i++) {
    printf("%02x", keyPair->publicKeyY[i]);
  }
  printf("\n");
  printf("     ↑ Byte 04 = uncompressed point\n");

  /* 3. C array format */
  printf("\n  3. C ARRAY FORMAT (để nhúng vào firmware)\n");
  printf("  ───────────────────────────────────────────\n");
  printf("     const uint8_t publicKeyX[32] = {\n       ");
  for (uint32 i = 0; i < CRYPTO_ECDSA_P256_KEY_SIZE; i++) {
    printf("0x%02x", keyPair->publicKeyX[i]);
    if (i < 31)
      printf(", ");
    if ((i + 1) % 8 == 0 && i < 31)
      printf("\n       ");
  }
  printf("\n     };\n");

  printf("\n[LƯU Ý BẢO MẬT]\n");
  printf("  ⚠ KHÔNG export private key dưới dạng plain text!\n");
  printf("  ⚠ Nếu cần backup, phải encrypt bằng AES trước\n");
  printf("  ✓ Public key có thể export tự do\n");
}

/*===========================================================================*/
/*                    VÍ DỤ 3.3: IMPORT KEY TỪ HEX                            */
/*===========================================================================*/
/**
 * @brief   Import key từ hex string vào Crypto Driver
 */
static void Example_ImportKey(void) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║  VÍ DỤ 3.3: IMPORT KEY TỪ HEX                                ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");

  printf("\n[TÌNH HUỐNG]\n");
  printf("  - Nhận public key từ OEM để verify firmware\n");
  printf("  - Key được cung cấp dưới dạng hex string\n");
  printf("  - Cần import vào Crypto Driver để sử dụng\n");

  /* Sample key (đây chỉ là ví dụ, không phải key thật) */
  const char *hexPublicKeyX = "6b17d1f2e12c4247f8bce6e563a440f2"
                              "77037d812deb33a0f4a13945d898c296";
  const char *hexPublicKeyY = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e16"
                              "2bce33576b315ececbb6406837bf51f5";

  printf("\n[INPUT (hex strings)]\n");
  printf("  Public Key X: %s\n", hexPublicKeyX);
  printf("  Public Key Y: %s\n", hexPublicKeyY);

  printf("\n[QUÁ TRÌNH IMPORT]\n\n");

  /* Bước 1: Convert hex string to bytes */
  printf("  BƯỚC 1: Convert hex string → byte array\n");
  printf("  ─────────────────────────────────────────\n");

  uint8 publicKeyX[CRYPTO_ECDSA_P256_KEY_SIZE];
  uint8 publicKeyY[CRYPTO_ECDSA_P256_KEY_SIZE];

  for (uint32 i = 0; i < CRYPTO_ECDSA_P256_KEY_SIZE; i++) {
    sscanf(&hexPublicKeyX[i * 2], "%2hhx", &publicKeyX[i]);
    sscanf(&hexPublicKeyY[i * 2], "%2hhx", &publicKeyY[i]);
  }

  printf("    ✓ Đã convert 64 hex chars → 32 bytes cho mỗi key\n");
  PrintHexFormatted("    Public Key X bytes:", publicKeyX, 32);

  /* Bước 2: Import vào Crypto Driver */
  printf("  BƯỚC 2: Gọi Crypto_ECDSA_SetPublicKey()\n");
  printf("  ────────────────────────────────────────\n");

  Std_ReturnType result =
      Crypto_ECDSA_SetPublicKey(KEY_SLOT_VERIFY, /* Key slot ID */
                                publicKeyX,      /* X coordinate */
                                publicKeyY,      /* Y coordinate */
                                CRYPTO_ECDSA_P256_KEY_SIZE);

  if (result == E_OK) {
    printf("    ✓ Public key đã được import vào slot %d\n", KEY_SLOT_VERIFY);
    printf("    → Có thể dùng để verify signatures\n");
  } else {
    printf("    ✗ Import thất bại!\n");
  }

  printf("\n[SỬ DỤNG KEY ĐÃ IMPORT]\n");
  printf("  - Key được lưu trong Crypto Driver memory\n");
  printf("  - Khi gọi Crypto_ECDSA_Verify(), truyền keyId = %d\n",
         KEY_SLOT_VERIFY);
  printf("  - Driver sẽ tự động lấy key từ slot để verify\n");
}

/*===========================================================================*/
/*                    VÍ DỤ 3.4: KEY STORAGE BEST PRACTICES                   */
/*===========================================================================*/
/**
 * @brief   Hướng dẫn lưu trữ key an toàn
 */
static void Example_KeyStorageBestPractices(void) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║  VÍ DỤ 3.4: KEY STORAGE BEST PRACTICES                       ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");

  printf("\n  ╔═══════════════════════════════════════════════════════════╗\n");
  printf("  ║            PRIVATE KEY STORAGE                            ║\n");
  printf("  ╠═══════════════════════════════════════════════════════════╣\n");
  printf("  ║                                                           ║\n");
  printf("  ║  ✗ KHÔNG LÀM:                                             ║\n");
  printf("  ║    - Lưu plain text trong Flash                           ║\n");
  printf("  ║    - Hardcode trong source code                           ║\n");
  printf("  ║    - Log ra console/file                                  ║\n");
  printf("  ║    - Truyền qua mạng không mã hóa                         ║\n");
  printf("  ║                                                           ║\n");
  printf("  ║  ✓ NÊN LÀM:                                               ║\n");
  printf("  ║    - Lưu trong HSM (Hardware Security Module)             ║\n");
  printf("  ║    - Lưu trong Secure Element                             ║\n");
  printf("  ║    - Lưu trong OTP (One-Time Programmable) if supported   ║\n");
  printf("  ║    - Encrypt bằng device-unique key nếu phải lưu Flash    ║\n");
  printf("  ║                                                           ║\n");
  printf("  ╚═══════════════════════════════════════════════════════════╝\n");

  printf("\n  ╔═══════════════════════════════════════════════════════════╗\n");
  printf("  ║            PUBLIC KEY STORAGE                             ║\n");
  printf("  ╠═══════════════════════════════════════════════════════════╣\n");
  printf("  ║                                                           ║\n");
  printf("  ║  Public key CÓ THỂ lưu ở bất kỳ đâu:                      ║\n");
  printf("  ║    - Flash (bootloader area)                              ║\n");
  printf("  ║    - OTP (để ngăn replace)                                ║\n");
  printf("  ║    - Certificate trong EEPROM                             ║\n");
  printf("  ║                                                           ║\n");
  printf("  ║  Tuy nhiên, cần đảm bảo INTEGRITY:                        ║\n");
  printf("  ║    - Attacker không thể replace bằng key của họ           ║\n");
  printf("  ║    - Dùng OTP hoặc verify chain of trust                  ║\n");
  printf("  ║                                                           ║\n");
  printf("  ╚═══════════════════════════════════════════════════════════╝\n");

  printf("\n  ╔═══════════════════════════════════════════════════════════╗\n");
  printf("  ║            AUTOSAR KEY MANAGEMENT                         ║\n");
  printf("  ╠═══════════════════════════════════════════════════════════╣\n");
  printf("  ║                                                           ║\n");
  printf("  ║  Trong AUTOSAR, keys được quản lý bởi:                    ║\n");
  printf("  ║                                                           ║\n");
  printf("  ║    KeyM (Key Manager)                                     ║\n");
  printf("  ║       ↓                                                   ║\n");
  printf("  ║    CryIf (Crypto Interface)                               ║\n");
  printf("  ║       ↓                                                   ║\n");
  printf("  ║    Crypto Driver (HSM/SW)                                 ║\n");
  printf("  ║                                                           ║\n");
  printf("  ║  Key được identify bằng keyId, không expose raw bytes     ║\n");
  printf("  ║                                                           ║\n");
  printf("  ╚═══════════════════════════════════════════════════════════╝\n");
}

/*===========================================================================*/
/*                    MAIN                                                    */
/*===========================================================================*/
int main(void) {
  printf("\n");
  printf("████████████████████████████████████████████████████████████████\n");
  printf("█       HALA ACADEMY - ECDSA KEY GENERATION EXAMPLES           █\n");
  printf("████████████████████████████████████████████████████████████████\n");

  /* Tạo key pair để dùng trong các ví dụ */
  Crypto_ECDSA_KeyPairType keyPair;

  Example_GenerateKeyPair(&keyPair);
  Example_ExportKey(&keyPair);
  Example_ImportKey();
  Example_KeyStorageBestPractices();

  printf("\n");
  printf("████████████████████████████████████████████████████████████████\n");
  printf("█                        HOÀN TẤT                              █\n");
  printf("████████████████████████████████████████████████████████████████\n");
  printf("\n");

  return 0;
}
