/*******************************************************************************
 * @file    example_04_ecdsa_sign_verify.c
 * @brief   Ví dụ 4: ECDSA Sign & Verify - Ký và xác thực chữ ký số
 *
 * @author  HALA Academy
 * @version 1.0.0
 * @date    2026-01-02
 *
 * @note    VÍ DỤ NÀY MINH HỌA:
 *          1. Quy trình ký message (Sign)
 *          2. Quy trình xác thực (Verify)
 *          3. Phát hiện message bị sửa đổi
 *          4. Phát hiện signature giả mạo
 *          5. Giải thích từng bước trong algorithm
 *
 * @compile gcc -o example_04 example_04_ecdsa_sign_verify.c \
 *              ../src/Crypto_ECDSA.c ../src/Crypto_SHA256.c \
 *              ../lib/micro-ecc/uECC.c \
 *              -I../include -I../lib/micro-ecc -Wall
 * @run     ./example_04
 ******************************************************************************/

#include "Crypto_ECDSA.h"
#include "Crypto_SHA256.h"
#include <stdio.h>
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

/*===========================================================================*/
/*                    VÍ DỤ 4.1: QUY TRÌNH KÝ (SIGNING)                       */
/*===========================================================================*/
/**
 * @brief   Minh họa chi tiết quy trình ký ECDSA
 *
 * @details ECDSA SIGN ALGORITHM:
 *
 *          Input:
 *            - d = private key (scalar)
 *            - m = message
 *
 *          Process:
 *            1. e = SHA256(m)                    [Hash message]
 *            2. z = leftmost bits of e           [Truncate nếu cần]
 *            3. k = random trong [1, n-1]        [Ephemeral key]
 *            4. (x1, y1) = k × G                 [Point multiplication]
 *            5. r = x1 mod n                     [Signature R]
 *            6. s = k^(-1) × (z + r×d) mod n     [Signature S]
 *
 *          Output:
 *            - Signature (r, s)
 */
static void Example_SigningProcess(const Crypto_ECDSA_KeyPairType *keyPair,
                                   uint8 *signature, uint32 *signatureLen) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║  VÍ DỤ 4.1: QUY TRÌNH KÝ ECDSA                               ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");

  const char *message = "AUTOSAR ECU Firmware v3.0 - Production Release";

  printf("\n[INPUT]\n");
  printf("  Message: \"%s\"\n", message);
  printf("  Message length: %zu bytes\n", strlen(message));

  printf("\n[QUY TRÌNH KÝ CHI TIẾT]\n");
  printf("═══════════════════════════════════════════════════════════════\n");

  /*=======================================================================
   * BƯỚC 1: HASH MESSAGE
   *=======================================================================*/
  printf("\n  BƯỚC 1: HASH MESSAGE\n");
  printf("  ─────────────────────\n");
  printf("    Công thức: e = SHA256(message)\n");
  printf("    Lý do: ECDSA ký trên hash, không phải message gốc\n");
  printf("           → Cho phép ký message có độ dài bất kỳ\n");
  printf("           → Hash có độ dài cố định (256 bits)\n\n");

  uint8 digest[CRYPTO_SHA256_DIGEST_SIZE];
  uint32 digestLen = sizeof(digest);

  Crypto_SHA256_Calculate((const uint8 *)message, (uint32)strlen(message),
                          digest, &digestLen);

  PrintHex("    Hash (e): ", digest, digestLen);

  /*=======================================================================
   * BƯỚC 2: SET PRIVATE KEY
   *=======================================================================*/
  printf("\n  BƯỚC 2: CHUẨN BỊ PRIVATE KEY\n");
  printf("  ────────────────────────────\n");
  printf("    Private key d được load vào Crypto Driver\n");
  printf("    Key slot: %d\n", KEY_SLOT_SIGN);

  Crypto_ECDSA_SetPrivateKey(KEY_SLOT_SIGN, keyPair->privateKey,
                             CRYPTO_ECDSA_P256_KEY_SIZE);

  printf("    ✓ Private key đã được set\n");

  /*=======================================================================
   * BƯỚC 3: TẠO SIGNATURE
   *=======================================================================*/
  printf("\n  BƯỚC 3: TẠO SIGNATURE\n");
  printf("  ──────────────────────\n");
  printf("    Algorithm nội bộ (trong Crypto_ECDSA_Sign):\n");
  printf("      1. Chọn k ngẫu nhiên trong [1, n-1]\n");
  printf("      2. Tính (x1, y1) = k × G\n");
  printf("      3. r = x1 mod n\n");
  printf("      4. s = k^(-1) × (hash + r × d) mod n\n");
  printf("      5. Signature = (r, s)\n\n");

  *signatureLen = CRYPTO_ECDSA_P256_SIG_SIZE;

  Std_ReturnType result = Crypto_ECDSA_Sign(KEY_SLOT_SIGN, digest, digestLen,
                                            signature, signatureLen);

  if (result == E_OK) {
    printf("    ✓ Signature tạo thành công!\n\n");
    PrintHex("    Signature R (32 bytes): ", signature, 32);
    PrintHex("    Signature S (32 bytes): ", signature + 32, 32);

    printf("\n  GIẢI THÍCH OUTPUT:\n");
    printf("  ───────────────────\n");
    printf("    - R: Tọa độ X của điểm k×G (mod n)\n");
    printf("    - S: Chứng minh rằng signer biết d mà không expose d\n");
    printf("    - Mỗi lần ký tạo signature KHÁC nhau (vì k ngẫu nhiên)\n");
    printf("    - Điều này KHÔNG phải lỗi, mà là feature bảo mật!\n");
  } else {
    printf("    ✗ Signing thất bại!\n");
  }
}

/*===========================================================================*/
/*                    VÍ DỤ 4.2: QUY TRÌNH VERIFY                             */
/*===========================================================================*/
/**
 * @brief   Minh họa chi tiết quy trình verify ECDSA
 *
 * @details ECDSA VERIFY ALGORITHM:
 *
 *          Input:
 *            - Q = public key (point)
 *            - m = message
 *            - (r, s) = signature
 *
 *          Process:
 *            1. e = SHA256(m)                    [Hash message]
 *            2. z = leftmost bits of e
 *            3. w = s^(-1) mod n                 [Inverse of s]
 *            4. u1 = z × w mod n
 *            5. u2 = r × w mod n
 *            6. (x1, y1) = u1 × G + u2 × Q       [Two point multiplications]
 *            7. Valid if r ≡ x1 (mod n)
 *
 *          Output:
 *            - VALID hoặc INVALID
 */
static void Example_VerifyProcess(const Crypto_ECDSA_KeyPairType *keyPair,
                                  const uint8 *signature, uint32 signatureLen) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║  VÍ DỤ 4.2: QUY TRÌNH VERIFY ECDSA                           ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");

  const char *message = "AUTOSAR ECU Firmware v3.0 - Production Release";

  printf("\n[INPUT]\n");
  printf("  Message: \"%s\"\n", message);
  PrintHex("  Signature R: ", signature, 32);
  PrintHex("  Signature S: ", signature + 32, 32);

  printf("\n[QUY TRÌNH VERIFY CHI TIẾT]\n");
  printf("═══════════════════════════════════════════════════════════════\n");

  /*=======================================================================
   * BƯỚC 1: HASH MESSAGE
   *=======================================================================*/
  printf("\n  BƯỚC 1: HASH MESSAGE (giống khi ký)\n");
  printf("  ────────────────────────────────────\n");
  printf("    Phải hash lại message để so sánh với signature\n");

  uint8 digest[CRYPTO_SHA256_DIGEST_SIZE];
  uint32 digestLen = sizeof(digest);

  Crypto_SHA256_Calculate((const uint8 *)message, (uint32)strlen(message),
                          digest, &digestLen);

  PrintHex("    Hash (e): ", digest, digestLen);

  /*=======================================================================
   * BƯỚC 2: SET PUBLIC KEY
   *=======================================================================*/
  printf("\n  BƯỚC 2: CHUẨN BỊ PUBLIC KEY\n");
  printf("  ────────────────────────────\n");
  printf("    Public key Q = (Qx, Qy) của signer\n");
  printf("    Thường được nhúng trong bootloader hoặc certificate\n");

  Crypto_ECDSA_SetPublicKey(KEY_SLOT_VERIFY, keyPair->publicKeyX,
                            keyPair->publicKeyY, CRYPTO_ECDSA_P256_KEY_SIZE);

  printf("    ✓ Public key đã được set\n");

  /*=======================================================================
   * BƯỚC 3: VERIFY SIGNATURE
   *=======================================================================*/
  printf("\n  BƯỚC 3: VERIFY SIGNATURE\n");
  printf("  ─────────────────────────\n");
  printf("    Algorithm nội bộ:\n");
  printf("      1. w = s^(-1) mod n\n");
  printf("      2. u1 = hash × w mod n\n");
  printf("      3. u2 = r × w mod n\n");
  printf("      4. P = u1×G + u2×Q (point add)\n");
  printf("      5. So sánh Px với r\n\n");

  Crypto_VerifyResultType verifyResult;

  Std_ReturnType result =
      Crypto_ECDSA_Verify(KEY_SLOT_VERIFY, digest, digestLen, signature,
                          signatureLen, &verifyResult);

  if (result == E_OK) {
    if (verifyResult == CRYPTO_E_VER_OK) {
      printf("  ╔════════════════════════════════════════════╗\n");
      printf("  ║  ✓ SIGNATURE HỢP LỆ!                       ║\n");
      printf("  ╠════════════════════════════════════════════╣\n");
      printf("  ║  Ý nghĩa:                                  ║\n");
      printf("  ║  1. Message chưa bị sửa đổi                ║\n");
      printf("  ║  2. Signature được tạo bởi người có        ║\n");
      printf("  ║     private key tương ứng với public key   ║\n");
      printf("  ║  3. Signature không bị forge               ║\n");
      printf("  ╚════════════════════════════════════════════╝\n");
    } else {
      printf("  ╔════════════════════════════════════════════╗\n");
      printf("  ║  ✗ SIGNATURE KHÔNG HỢP LỆ!                 ║\n");
      printf("  ╚════════════════════════════════════════════╝\n");
    }
  }
}

/*===========================================================================*/
/*                    VÍ DỤ 4.3: PHÁT HIỆN MESSAGE BỊ SỬA ĐỔI                 */
/*===========================================================================*/
static void
Example_DetectTamperedMessage(const Crypto_ECDSA_KeyPairType *keyPair,
                              const uint8 *originalSignature,
                              uint32 signatureLen) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║  VÍ DỤ 4.3: PHÁT HIỆN MESSAGE BỊ SỬA ĐỔI                     ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");

  printf("\n[TÌNH HUỐNG TẤN CÔNG]\n");
  printf("  - Attacker chặn firmware update\n");
  printf("  - Sửa đổi firmware (inject malware)\n");
  printf("  - Gửi firmware đã sửa + signature gốc cho ECU\n");

  /* Message bị sửa */
  const char *tamperedMessage = "AUTOSAR ECU Firmware v3.0 - HACKED Release!";

  printf("\n  Original: \"AUTOSAR ECU Firmware v3.0 - Production Release\"\n");
  printf("  Tampered: \"%s\"\n", tamperedMessage);

  printf("\n[VERIFY VỚI MESSAGE ĐÃ BỊ SỬA]\n");

  /* Hash message mới */
  uint8 tamperedDigest[CRYPTO_SHA256_DIGEST_SIZE];
  uint32 digestLen = sizeof(tamperedDigest);

  Crypto_SHA256_Calculate((const uint8 *)tamperedMessage,
                          (uint32)strlen(tamperedMessage), tamperedDigest,
                          &digestLen);

  printf("  Hash của message bị sửa:\n");
  PrintHex("    ", tamperedDigest, digestLen);

  /* Set public key */
  Crypto_ECDSA_SetPublicKey(KEY_SLOT_VERIFY, keyPair->publicKeyX,
                            keyPair->publicKeyY, CRYPTO_ECDSA_P256_KEY_SIZE);

  /* Verify */
  Crypto_VerifyResultType verifyResult;

  Crypto_ECDSA_Verify(KEY_SLOT_VERIFY, tamperedDigest, digestLen,
                      originalSignature, /* Signature gốc */
                      signatureLen, &verifyResult);

  printf("\n[KẾT QUẢ]\n");

  if (verifyResult == CRYPTO_E_VER_NOT_OK) {
    printf("  ╔════════════════════════════════════════════════════════╗\n");
    printf("  ║  ✓ ĐÃ PHÁT HIỆN MESSAGE BỊ SỬA ĐỔI!                    ║\n");
    printf("  ╠════════════════════════════════════════════════════════╣\n");
    printf("  ║  Reason:                                               ║\n");
    printf("  ║  - Hash(tampered) ≠ Hash(original)                     ║\n");
    printf("  ║  - Signature chỉ valid cho hash gốc                    ║\n");
    printf("  ║  - Attacker không thể tạo signature mới                ║\n");
    printf("  ║    vì không có private key                             ║\n");
    printf("  ║                                                        ║\n");
    printf("  ║  Action: ECU reject firmware update!                   ║\n");
    printf("  ╚════════════════════════════════════════════════════════╝\n");
  } else {
    printf("  ✗ Không phát hiện được! (Bug hoặc collision attack)\n");
  }
}

/*===========================================================================*/
/*                    VÍ DỤ 4.4: PHÁT HIỆN SIGNATURE GIẢ MẠO                  */
/*===========================================================================*/
static void
Example_DetectForgedSignature(const Crypto_ECDSA_KeyPairType *keyPair) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║  VÍ DỤ 4.4: PHÁT HIỆN SIGNATURE GIẢ MẠO                      ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");

  printf("\n[TÌNH HUỐNG TẤN CÔNG]\n");
  printf("  - Attacker tạo firmware malware\n");
  printf("  - Cố gắng tự tạo signature giả\n");
  printf("  - Gửi malware + forged signature cho ECU\n");

  const char *attackerMessage = "Attacker Malware Firmware v1.0";

  /* Attacker thử tạo signature ngẫu nhiên */
  uint8 forgedSignature[64] = {
      0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44,
      0x55, 0x66, 0x77, 0x88, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
      0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
      /* S part */
      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0f, 0x1e, 0x2d, 0x3c,
      0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

  printf("\n  Attacker's message: \"%s\"\n", attackerMessage);
  PrintHex("  Forged signature R: ", forgedSignature, 32);
  PrintHex("  Forged signature S: ", forgedSignature + 32, 32);

  /* Hash message */
  uint8 digest[CRYPTO_SHA256_DIGEST_SIZE];
  uint32 digestLen = sizeof(digest);

  Crypto_SHA256_Calculate((const uint8 *)attackerMessage,
                          (uint32)strlen(attackerMessage), digest, &digestLen);

  /* Set legitimate public key */
  Crypto_ECDSA_SetPublicKey(KEY_SLOT_VERIFY, keyPair->publicKeyX,
                            keyPair->publicKeyY, CRYPTO_ECDSA_P256_KEY_SIZE);

  /* Verify forged signature */
  Crypto_VerifyResultType verifyResult;

  printf("\n[VERIFY FORGED SIGNATURE]\n");

  Crypto_ECDSA_Verify(KEY_SLOT_VERIFY, digest, digestLen, forgedSignature, 64,
                      &verifyResult);

  if (verifyResult == CRYPTO_E_VER_NOT_OK) {
    printf("  ╔════════════════════════════════════════════════════════╗\n");
    printf("  ║  ✓ ĐÃ PHÁT HIỆN SIGNATURE GIẢ MẠO!                     ║\n");
    printf("  ╠════════════════════════════════════════════════════════╣\n");
    printf("  ║  Reason:                                               ║\n");
    printf("  ║  - Để tạo valid signature, cần BIẾT private key        ║\n");
    printf("  ║  - ECDLP problem: không thể tính d từ Q                ║\n");
    printf("  ║  - Xác suất đoán đúng signature: 1/2^256              ║\n");
    printf("  ║    (nhỏ hơn xác suất trúng lottery 10^60 lần)          ║\n");
    printf("  ║                                                        ║\n");
    printf("  ║  Action: ECU reject firmware!                          ║\n");
    printf("  ╚════════════════════════════════════════════════════════╝\n");
  } else {
    printf("  ✗ Signature được accept! (Should NOT happen!)\n");
  }
}

/*===========================================================================*/
/*                    MAIN                                                    */
/*===========================================================================*/
int main(void) {
  printf("\n");
  printf("████████████████████████████████████████████████████████████████\n");
  printf("█       HALA ACADEMY - ECDSA SIGN & VERIFY EXAMPLES            █\n");
  printf("████████████████████████████████████████████████████████████████\n");

  /* Tạo key pair */
  printf("\n[CHUẨN BỊ] Tạo key pair...\n");
  Crypto_ECDSA_KeyPairType keyPair;
  Crypto_ECDSA_GenerateKeyPair(&keyPair);
  printf("✓ Key pair đã tạo\n");

  /* Chạy các ví dụ */
  uint8 signature[CRYPTO_ECDSA_P256_SIG_SIZE];
  uint32 signatureLen = sizeof(signature);

  Example_SigningProcess(&keyPair, signature, &signatureLen);
  Example_VerifyProcess(&keyPair, signature, signatureLen);
  Example_DetectTamperedMessage(&keyPair, signature, signatureLen);
  Example_DetectForgedSignature(&keyPair);

  printf("\n");
  printf("████████████████████████████████████████████████████████████████\n");
  printf("█                        HOÀN TẤT                              █\n");
  printf("████████████████████████████████████████████████████████████████\n");
  printf("\n");

  return 0;
}
