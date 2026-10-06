/*******************************************************************************
 * @file    example_01_sha256_basic.c
 * @brief   Ví dụ 1: SHA-256 Cơ bản - Hash các loại dữ liệu khác nhau
 *
 * @author  HALA Academy
 * @version 1.0.0
 * @date    2026-01-02
 *
 * @note    VÍ DỤ NÀY MINH HỌA:
 *          1. Hash chuỗi ngắn (string)
 *          2. Hash chuỗi rỗng
 *          3. Hash dữ liệu nhị phân (binary)
 *          4. So sánh với FIPS 180-4 test vectors
 *
 * @compile gcc -o example_01 example_01_sha256_basic.c ../src/Crypto_SHA256.c \
 *              -I../include -Wall
 * @run     ./example_01
 ******************************************************************************/

#include "Crypto_SHA256.h"
#include <stdio.h>
#include <string.h>

/*===========================================================================*/
/*                    HELPER FUNCTION                                         */
/*===========================================================================*/
/**
 * @brief   In digest dưới dạng hex
 */
static void PrintDigest(const char *label, const uint8 *digest, uint32 length) {
  uint32 i;
  printf("%s", label);
  for (i = 0; i < length; i++) {
    printf("%02x", digest[i]);
  }
  printf("\n");
}

/**
 * @brief   So sánh digest với expected hex string
 */
static int VerifyDigest(const uint8 *digest, const char *expectedHex) {
  char calculatedHex[65];
  uint32 i;

  for (i = 0; i < 32; i++) {
    sprintf(&calculatedHex[i * 2], "%02x", digest[i]);
  }
  calculatedHex[64] = '\0';

  return strcmp(calculatedHex, expectedHex) == 0;
}

/*===========================================================================*/
/*                    VÍ DỤ 1.1: HASH CHUỖI NGẮN                              */
/*===========================================================================*/
/**
 * @brief   Hash chuỗi "abc" - Test vector chuẩn từ FIPS 180-4
 *
 * @details SHA-256 hoạt động như sau:
 *          1. Nhận input là dãy bytes bất kỳ
 *          2. Padding để độ dài = bội số 512 bits
 *          3. Xử lý từng block 512-bit qua 64 rounds
 *          4. Output là digest 256-bit (32 bytes)
 */
static void Example_HashShortString(void) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║  VÍ DỤ 1.1: HASH CHUỖI NGẮN                                  ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");

  /*-----------------------------------------------------------------------
   * BƯỚC 1: Chuẩn bị input
   *-----------------------------------------------------------------------*/
  const char *message = "abc";
  printf("\n[BƯỚC 1] Chuẩn bị input\n");
  printf("  - Message: \"%s\"\n", message);
  printf("  - Độ dài: %zu bytes\n", strlen(message));
  printf("  - Hex: 61 62 63 (a=0x61, b=0x62, c=0x63)\n");

  /*-----------------------------------------------------------------------
   * BƯỚC 2: Chuẩn bị buffer output
   *-----------------------------------------------------------------------*/
  uint8 digest[CRYPTO_SHA256_DIGEST_SIZE];
  uint32 digestLen = sizeof(digest);

  printf("\n[BƯỚC 2] Chuẩn bị buffer output\n");
  printf("  - Buffer size: %u bytes\n", digestLen);
  printf("  - SHA-256 luôn output 32 bytes (256 bits)\n");

  /*-----------------------------------------------------------------------
   * BƯỚC 3: Gọi API hash
   *-----------------------------------------------------------------------*/
  printf("\n[BƯỚC 3] Gọi Crypto_SHA256_Calculate()\n");
  printf("  - Đây là single-call API (Init + Update + Finish trong 1 lần)\n");

  Std_ReturnType result = Crypto_SHA256_Calculate(
      (const uint8 *)message, (uint32)strlen(message), digest, &digestLen);

  /*-----------------------------------------------------------------------
   * BƯỚC 4: Kiểm tra kết quả
   *-----------------------------------------------------------------------*/
  printf("\n[BƯỚC 4] Kết quả\n");

  if (result == E_OK) {
    printf("  - Status: E_OK (thành công)\n");
    printf("  - Output length: %u bytes\n", digestLen);
    PrintDigest("  - Digest: ", digest, digestLen);

    /* So sánh với FIPS 180-4 test vector */
    const char *expected = "ba7816bf8f01cfea414140de5dae2223"
                           "b00361a396177a9cb410ff61f20015ad";
    printf("  - Expected: %s\n", expected);

    if (VerifyDigest(digest, expected)) {
      printf("\n  ✓ PASS: Kết quả khớp với FIPS 180-4!\n");
    } else {
      printf("\n  ✗ FAIL: Kết quả không khớp!\n");
    }
  } else {
    printf("  - Status: E_NOT_OK (thất bại)\n");
  }
}

/*===========================================================================*/
/*                    VÍ DỤ 1.2: HASH CHUỖI RỖNG                              */
/*===========================================================================*/
/**
 * @brief   Hash chuỗi rỗng (empty string)
 *
 * @details Đây là edge case quan trọng:
 *          - Input: "" (0 bytes)
 *          - SHA-256 vẫn output 32 bytes
 *          - Có test vector chuẩn cho trường hợp này
 */
static void Example_HashEmptyString(void) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║  VÍ DỤ 1.2: HASH CHUỖI RỖNG                                  ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");

  /*-----------------------------------------------------------------------
   * BƯỚC 1: Input rỗng
   *-----------------------------------------------------------------------*/
  const char *message = ""; /* Empty string */
  printf("\n[BƯỚC 1] Chuẩn bị input\n");
  printf("  - Message: \"\" (chuỗi rỗng)\n");
  printf("  - Độ dài: 0 bytes\n");
  printf("  - Lưu ý: Input rỗng vẫn hợp lệ với SHA-256!\n");

  /*-----------------------------------------------------------------------
   * BƯỚC 2: Hash
   *-----------------------------------------------------------------------*/
  uint8 digest[CRYPTO_SHA256_DIGEST_SIZE];
  uint32 digestLen = sizeof(digest);

  printf("\n[BƯỚC 2] Thực hiện hash\n");
  printf("  - SHA-256 sẽ chỉ padding và xử lý 1 block\n");

  Std_ReturnType result =
      Crypto_SHA256_Calculate((const uint8 *)message, 0, /* length = 0 */
                              digest, &digestLen);

  /*-----------------------------------------------------------------------
   * BƯỚC 3: Kết quả
   *-----------------------------------------------------------------------*/
  printf("\n[BƯỚC 3] Kết quả\n");

  if (result == E_OK) {
    PrintDigest("  - Digest: ", digest, digestLen);

    const char *expected = "e3b0c44298fc1c149afbf4c8996fb924"
                           "27ae41e4649b934ca495991b7852b855";
    printf("  - Expected: %s\n", expected);

    if (VerifyDigest(digest, expected)) {
      printf("\n  ✓ PASS: Hash của empty string đúng!\n");
    } else {
      printf("\n  ✗ FAIL!\n");
    }
  }

  printf("\n  Giải thích:\n");
  printf("  - Mỗi input khác nhau → digest khác nhau\n");
  printf("  - Ngay cả input rỗng cũng có digest riêng\n");
  printf("  - Không thể suy ra input từ digest (one-way function)\n");
}

/*===========================================================================*/
/*                    VÍ DỤ 1.3: HASH CHUỖI DÀI                               */
/*===========================================================================*/
/**
 * @brief   Hash chuỗi dài hơn 1 block (>64 bytes)
 *
 * @details Khi message > 64 bytes:
 *          - SHA-256 chia thành nhiều blocks
 *          - Xử lý tuần tự từng block
 *          - Kết quả cuối cùng vẫn là 32 bytes
 */
static void Example_HashLongString(void) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║  VÍ DỤ 1.3: HASH CHUỖI DÀI (> 64 BYTES)                      ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");

  /* Test vector từ FIPS 180-4: 448 bits = 56 bytes (vừa đúng trước padding) */
  const char *message =
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

  printf("\n[BƯỚC 1] Chuẩn bị input\n");
  printf("  - Message: \"%s\"\n", message);
  printf("  - Độ dài: %zu bytes (> 64 bytes block size)\n", strlen(message));
  printf("  - Sẽ cần xử lý 2 blocks sau khi padding\n");

  uint8 digest[CRYPTO_SHA256_DIGEST_SIZE];
  uint32 digestLen = sizeof(digest);

  printf("\n[BƯỚC 2] Hash\n");
  Crypto_SHA256_Calculate((const uint8 *)message, (uint32)strlen(message),
                          digest, &digestLen);

  printf("\n[BƯỚC 3] Kết quả\n");
  PrintDigest("  - Digest: ", digest, digestLen);

  const char *expected = "248d6a61d20638b8e5c026930c3e6039"
                         "a33ce45964ff2167f6ecedd419db06c1";
  printf("  - Expected: %s\n", expected);

  if (VerifyDigest(digest, expected)) {
    printf("\n  ✓ PASS: Multi-block hash đúng!\n");
  }
}

/*===========================================================================*/
/*                    VÍ DỤ 1.4: HASH BINARY DATA                             */
/*===========================================================================*/
/**
 * @brief   Hash dữ liệu nhị phân (không phải text)
 *
 * @details SHA-256 hoạt động với bất kỳ dữ liệu nào:
 *          - Text (ASCII, UTF-8)
 *          - Binary (executable, image, firmware)
 *          - Có thể chứa byte 0x00
 */
static void Example_HashBinaryData(void) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║  VÍ DỤ 1.4: HASH DỮ LIỆU BINARY                              ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");

  /* Mô phỏng header của một firmware binary */
  uint8 binaryData[] = {0x7F, 0x45, 0x4C, 0x46, /* ELF magic number */
                        0x02, 0x01, 0x01,
                        0x00, /* 64-bit, little endian, version */
                        0x00, 0x00, 0x00, 0x00, /* padding */
                        0x00, 0x00, 0x00, 0x00, /* padding */
                        0x02, 0x00,             /* executable */
                        0x3E, 0x00,             /* x86-64 */
                        0x01, 0x00, 0x00, 0x00, /* version */
                        /* Entry point, program header offset, etc. */
                        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  uint32 dataLen = sizeof(binaryData);

  printf("\n[BƯỚC 1] Chuẩn bị binary data\n");
  printf("  - Mô phỏng: ELF file header\n");
  printf("  - Độ dài: %u bytes\n", dataLen);
  printf("  - Hex dump:\n    ");
  for (uint32 i = 0; i < dataLen; i++) {
    printf("%02x ", binaryData[i]);
    if ((i + 1) % 16 == 0)
      printf("\n    ");
  }
  printf("\n");

  printf("\n[BƯỚC 2] Hash binary data\n");
  printf("  - SHA-256 xử lý bytes, không quan tâm encoding\n");
  printf("  - Có thể hash bất kỳ dữ liệu gì: text, image, executable\n");

  uint8 digest[CRYPTO_SHA256_DIGEST_SIZE];
  uint32 digestLen = sizeof(digest);

  Crypto_SHA256_Calculate(binaryData, dataLen, digest, &digestLen);

  printf("\n[BƯỚC 3] Kết quả\n");
  PrintDigest("  - Digest: ", digest, digestLen);

  printf("\n  Ứng dụng thực tế:\n");
  printf("  - Verify firmware integrity (Secure Boot)\n");
  printf("  - Kiểm tra file download không bị corrupt\n");
  printf("  - Digital forensics (identify files by hash)\n");
}

/*===========================================================================*/
/*                    VÍ DỤ 1.5: SENSITIVITY TEST                             */
/*===========================================================================*/
/**
 * @brief   Minh họa tính nhạy cảm của hash (avalanche effect)
 *
 * @details Thay đổi 1 bit input → ~50% bits output thay đổi
 *          Đây là tính chất quan trọng của cryptographic hash.
 */
static void Example_SensitivityTest(void) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║  VÍ DỤ 1.5: AVALANCHE EFFECT (1 bit thay đổi)                ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");

  const char *msg1 = "Hello World";
  const char *msg2 = "Hello World!"; /* Thêm 1 ký tự */
  const char *msg3 = "hello World";  /* Đổi H thành h */

  uint8 digest1[CRYPTO_SHA256_DIGEST_SIZE];
  uint8 digest2[CRYPTO_SHA256_DIGEST_SIZE];
  uint8 digest3[CRYPTO_SHA256_DIGEST_SIZE];
  uint32 len = CRYPTO_SHA256_DIGEST_SIZE;

  Crypto_SHA256_Calculate((const uint8 *)msg1, strlen(msg1), digest1, &len);
  Crypto_SHA256_Calculate((const uint8 *)msg2, strlen(msg2), digest2, &len);
  Crypto_SHA256_Calculate((const uint8 *)msg3, strlen(msg3), digest3, &len);

  printf("\n[So sánh hash khi thay đổi nhỏ trong input]\n\n");

  printf("Message 1: \"%s\"\n", msg1);
  PrintDigest("Digest 1:  ", digest1, len);

  printf("\nMessage 2: \"%s\" (thêm '!')\n", msg2);
  PrintDigest("Digest 2:  ", digest2, len);

  printf("\nMessage 3: \"%s\" (đổi H→h)\n", msg3);
  PrintDigest("Digest 3:  ", digest3, len);

  /* Đếm số bits khác nhau */
  int diffBits12 = 0, diffBits13 = 0;
  for (int i = 0; i < 32; i++) {
    uint8 xor12 = digest1[i] ^ digest2[i];
    uint8 xor13 = digest1[i] ^ digest3[i];
    for (int b = 0; b < 8; b++) {
      if (xor12 & (1 << b))
        diffBits12++;
      if (xor13 & (1 << b))
        diffBits13++;
    }
  }

  printf("\n[Phân tích]\n");
  printf("  - Digest 1 vs 2: %d bits khác nhau (%.1f%%)\n", diffBits12,
         diffBits12 * 100.0 / 256);
  printf("  - Digest 1 vs 3: %d bits khác nhau (%.1f%%)\n", diffBits13,
         diffBits13 * 100.0 / 256);
  printf("  - Lý tưởng: ~50%% bits thay đổi (avalanche effect)\n");
  printf("\n  → Không thể đoán input từ output!\n");
}

/*===========================================================================*/
/*                    MAIN                                                    */
/*===========================================================================*/
int main(void) {
  printf("\n");
  printf("████████████████████████████████████████████████████████████████\n");
  printf("█       HALA ACADEMY - SHA-256 BASIC EXAMPLES                  █\n");
  printf("████████████████████████████████████████████████████████████████\n");

  /* Chạy các ví dụ */
  Example_HashShortString();
  Example_HashEmptyString();
  Example_HashLongString();
  Example_HashBinaryData();
  Example_SensitivityTest();

  printf("\n");
  printf("████████████████████████████████████████████████████████████████\n");
  printf("█                        HOÀN TẤT                              █\n");
  printf("████████████████████████████████████████████████████████████████\n");
  printf("\n");

  return 0;
}
