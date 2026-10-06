/*******************************************************************************
 * @file    example_02_sha256_streaming.c
 * @brief   Ví dụ 2: SHA-256 Streaming Mode - Hash dữ liệu lớn theo chunks
 *
 * @author  HALA Academy
 * @version 1.0.0
 * @date    2026-01-02
 *
 * @note    VÍ DỤ NÀY MINH HỌA:
 *          1. Streaming mode: START → UPDATE (nhiều lần) → FINISH
 *          2. Mô phỏng hash firmware lớn
 *          3. So sánh streaming vs single-call
 *          4. Ứng dụng trong Secure Boot
 *
 * @compile gcc -o example_02 example_02_sha256_streaming.c
 *../src/Crypto_SHA256.c \ -I../include -Wall
 * @run     ./example_02
 ******************************************************************************/

#include "Crypto_SHA256.h"
#include <stdio.h>
#include <string.h>

/*===========================================================================*/
/*                    HELPER FUNCTIONS                                        */
/*===========================================================================*/
static void PrintDigest(const char *label, const uint8 *digest, uint32 length) {
  printf("%s", label);
  for (uint32 i = 0; i < length; i++) {
    printf("%02x", digest[i]);
  }
  printf("\n");
}

static int CompareDigests(const uint8 *d1, const uint8 *d2, uint32 len) {
  for (uint32 i = 0; i < len; i++) {
    if (d1[i] != d2[i])
      return 0;
  }
  return 1;
}

/*===========================================================================*/
/*                    VÍ DỤ 2.1: STREAMING MODE CƠ BẢN                        */
/*===========================================================================*/
/**
 * @brief   Minh họa streaming API: Init → Update → Finish
 *
 * @details TẠI SAO CẦN STREAMING?
 *
 *          Trong ECU automotive:
 *          - RAM rất hạn chế (vài KB đến vài MB)
 *          - Firmware có thể lớn (hàng MB)
 *          - Không thể load toàn bộ firmware vào RAM
 *
 *          Giải pháp:
 *          - Đọc firmware từng chunk (ví dụ 4KB)
 *          - Hash từng chunk bằng Update()
 *          - Kết thúc bằng Finish() để lấy digest
 */
static void Example_StreamingBasic(void) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║  VÍ DỤ 2.1: STREAMING MODE CƠ BẢN                            ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");

  /* Chia message thành 3 parts */
  const char *part1 = "Hello, ";
  const char *part2 = "AUTOSAR ";
  const char *part3 = "World!";

  printf("\n[Tình huống]\n");
  printf("  Message đầy đủ: \"Hello, AUTOSAR World!\"\n");
  printf("  Được chia thành:\n");
  printf("    Part 1: \"%s\" (%zu bytes)\n", part1, strlen(part1));
  printf("    Part 2: \"%s\" (%zu bytes)\n", part2, strlen(part2));
  printf("    Part 3: \"%s\" (%zu bytes)\n", part3, strlen(part3));

  /*=======================================================================
   * PHƯƠNG PHÁP 1: STREAMING (Init → Update → Finish)
   *=======================================================================*/
  printf("\n[PHƯƠNG PHÁP 1: STREAMING]\n\n");

  Crypto_SHA256_ContextType ctx;
  uint8 digestStreaming[CRYPTO_SHA256_DIGEST_SIZE];
  uint32 digestLen = sizeof(digestStreaming);

  /* BƯỚC 1: Init - Khởi tạo context */
  printf("  BƯỚC 1: Crypto_SHA256_Init(&ctx)\n");
  printf("          → Khởi tạo state H0..H7 với hằng số FIPS\n");
  printf("          → Reset bitCount = 0\n");
  printf("          → Clear buffer\n");
  Crypto_SHA256_Init(&ctx);
  printf("          ✓ Context đã được khởi tạo\n");

  /* BƯỚC 2: Update - Thêm part 1 */
  printf("\n  BƯỚC 2: Crypto_SHA256_Update(&ctx, part1, %zu)\n", strlen(part1));
  printf("          → Thêm \"%s\" vào buffer\n", part1);
  printf("          → Buffer chưa đủ 64 bytes nên chưa xử lý\n");
  Crypto_SHA256_Update(&ctx, (const uint8 *)part1, (uint32)strlen(part1));
  printf("          ✓ Part 1 đã được buffer\n");

  /* BƯỚC 3: Update - Thêm part 2 */
  printf("\n  BƯỚC 3: Crypto_SHA256_Update(&ctx, part2, %zu)\n", strlen(part2));
  printf("          → Thêm \"%s\" vào buffer\n", part2);
  Crypto_SHA256_Update(&ctx, (const uint8 *)part2, (uint32)strlen(part2));
  printf("          ✓ Part 2 đã được buffer\n");

  /* BƯỚC 4: Update - Thêm part 3 */
  printf("\n  BƯỚC 4: Crypto_SHA256_Update(&ctx, part3, %zu)\n", strlen(part3));
  printf("          → Thêm \"%s\" vào buffer\n", part3);
  Crypto_SHA256_Update(&ctx, (const uint8 *)part3, (uint32)strlen(part3));
  printf("          ✓ Part 3 đã được buffer\n");

  /* BƯỚC 5: Finish - Padding và xuất digest */
  printf("\n  BƯỚC 5: Crypto_SHA256_Finish(&ctx, digest, &len)\n");
  printf("          → Thêm padding (0x80 + zeros + length)\n");
  printf("          → Xử lý block cuối cùng\n");
  printf("          → Xuất H0..H7 thành digest 32 bytes\n");
  Crypto_SHA256_Finish(&ctx, digestStreaming, &digestLen);
  printf("          ✓ Digest đã được tạo\n");

  PrintDigest("\n  Streaming Result: ", digestStreaming, digestLen);

  /*=======================================================================
   * PHƯƠNG PHÁP 2: SINGLE CALL (để so sánh)
   *=======================================================================*/
  printf("\n[PHƯƠNG PHÁP 2: SINGLE CALL (để verify)]\n\n");

  /* Ghép message */
  char fullMessage[100];
  strcpy(fullMessage, part1);
  strcat(fullMessage, part2);
  strcat(fullMessage, part3);

  uint8 digestSingle[CRYPTO_SHA256_DIGEST_SIZE];
  digestLen = sizeof(digestSingle);

  printf("  Full message: \"%s\"\n", fullMessage);
  Crypto_SHA256_Calculate((const uint8 *)fullMessage,
                          (uint32)strlen(fullMessage), digestSingle,
                          &digestLen);

  PrintDigest("  Single-call Result: ", digestSingle, digestLen);

  /*=======================================================================
   * SO SÁNH KẾT QUẢ
   *=======================================================================*/
  printf("\n[KẾT LUẬN]\n");

  if (CompareDigests(digestStreaming, digestSingle,
                     CRYPTO_SHA256_DIGEST_SIZE)) {
    printf("  ✓ HAI PHƯƠNG PHÁP CHO CÙNG KẾT QUẢ!\n");
    printf("  → Streaming mode hoạt động chính xác\n");
    printf("  → Có thể hash dữ liệu lớn mà không cần load hết vào RAM\n");
  } else {
    printf("  ✗ Kết quả khác nhau - có lỗi!\n");
  }
}

/*===========================================================================*/
/*                    VÍ DỤ 2.2: MÔ PHỎNG FIRMWARE VERIFICATION               */
/*===========================================================================*/
/**
 * @brief   Mô phỏng quy trình Secure Boot verification
 *
 * @details SECURE BOOT WORKFLOW:
 *
 *          1. Bootloader khởi động
 *          2. Đọc firmware từ Flash theo từng page (4KB)
 *          3. Hash từng page bằng streaming
 *          4. So sánh digest với giá trị trusted (trong OTP/HSM)
 *          5. Nếu khớp → boot tiếp; Nếu không → reject
 */
static void Example_FirmwareVerification(void) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║  VÍ DỤ 2.2: MÔ PHỎNG FIRMWARE VERIFICATION (SECURE BOOT)     ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");

  /*-----------------------------------------------------------------------
   * Mô phỏng firmware trong Flash (thực tế có thể vài MB)
   *-----------------------------------------------------------------------*/
  printf("\n[TÌNH HUỐNG]\n");
  printf("  - ECU cần verify firmware trước khi boot\n");
  printf("  - Firmware size: 5 pages (mỗi page 64 bytes trong demo)\n");
  printf("  - RAM chỉ có 128 bytes (không đủ chứa toàn bộ firmware)\n");
  printf("  - Giải pháp: Hash từng page, không load hết vào RAM\n");

  /* Mô phỏng 5 firmware pages */
  const char *firmwarePages[] = {
      "[Page 0] RESET_HANDLER: Jump to main, init stack, init .bss  ", /* 64
                                                                          bytes
                                                                        */
      "[Page 1] MAIN_LOOP: Read sensors, process data, output control",
      "[Page 2] CAN_DRIVER: Init CAN, TX/RX handlers, filter config  ",
      "[Page 3] CRYPTO_LIB: AES, SHA256, secure key storage functions",
      "[Page 4] CONFIG_DATA: Calibration values, VIN, ECU serial no. "};
  uint32 numPages = 5;

  printf("\n[FIRMWARE CONTENTS]\n");
  for (uint32 i = 0; i < numPages; i++) {
    printf("  Page %u: %s\n", i, firmwarePages[i]);
  }

  /*-----------------------------------------------------------------------
   * Hash firmware page by page
   *-----------------------------------------------------------------------*/
  printf("\n[HASH PROCESS - STREAMING MODE]\n\n");

  Crypto_SHA256_ContextType ctx;
  uint8 calculatedDigest[CRYPTO_SHA256_DIGEST_SIZE];
  uint32 digestLen = sizeof(calculatedDigest);

  /* START */
  printf("  1. Crypto_SHA256_Init()\n");
  printf("     → Bootloader bắt đầu verification\n");
  Crypto_SHA256_Init(&ctx);

  /* UPDATE từng page */
  for (uint32 i = 0; i < numPages; i++) {
    const char *page = firmwarePages[i];
    uint32 pageSize = (uint32)strlen(page);

    printf("\n  %u. Processing Page %u (%u bytes)\n", i + 2, i, pageSize);
    printf("     → Đọc page từ Flash vào buffer tạm\n");
    printf("     → Crypto_SHA256_Update(ctx, page, %u)\n", pageSize);
    printf("     → Giải phóng buffer (RAM được tái sử dụng)\n");

    Crypto_SHA256_Update(&ctx, (const uint8 *)page, pageSize);
  }

  /* FINISH */
  printf("\n  %u. Crypto_SHA256_Finish()\n", numPages + 2);
  printf("     → Thực hiện padding\n");
  printf("     → Xuất digest cuối cùng\n");
  Crypto_SHA256_Finish(&ctx, calculatedDigest, &digestLen);

  PrintDigest("\n  Calculated Firmware Hash: ", calculatedDigest, digestLen);

  /*-----------------------------------------------------------------------
   * So sánh với trusted hash
   *-----------------------------------------------------------------------*/
  printf("\n[VERIFICATION]\n");

  /* Tính trusted hash (bằng single-call để có reference) */
  char fullFirmware[512] = "";
  for (uint32 i = 0; i < numPages; i++) {
    strcat(fullFirmware, firmwarePages[i]);
  }

  uint8 trustedDigest[CRYPTO_SHA256_DIGEST_SIZE];
  digestLen = sizeof(trustedDigest);
  Crypto_SHA256_Calculate((const uint8 *)fullFirmware,
                          (uint32)strlen(fullFirmware), trustedDigest,
                          &digestLen);

  PrintDigest("  Trusted Hash (from OTP): ", trustedDigest, digestLen);

  printf("\n  So sánh...\n");

  if (CompareDigests(calculatedDigest, trustedDigest,
                     CRYPTO_SHA256_DIGEST_SIZE)) {
    printf("\n  ╔════════════════════════════════════════════╗\n");
    printf("  ║  ✓ VERIFICATION PASSED!                    ║\n");
    printf("  ║  → Firmware chưa bị sửa đổi                ║\n");
    printf("  ║  → Bootloader tiếp tục boot                ║\n");
    printf("  ╚════════════════════════════════════════════╝\n");
  } else {
    printf("\n  ╔════════════════════════════════════════════╗\n");
    printf("  ║  ✗ VERIFICATION FAILED!                    ║\n");
    printf("  ║  → Firmware có thể bị sửa đổi hoặc corrupt ║\n");
    printf("  ║  → Bootloader từ chối boot                 ║\n");
    printf("  ╚════════════════════════════════════════════╝\n");
  }
}

/*===========================================================================*/
/*                    VÍ DỤ 2.3: PHÁT HIỆN FIRMWARE CORRUPT                   */
/*===========================================================================*/
/**
 * @brief   Phát hiện firmware bị corrupt 1 byte
 */
static void Example_CorruptedFirmware(void) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║  VÍ DỤ 2.3: PHÁT HIỆN FIRMWARE CORRUPT (1 BYTE)              ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");

  /* Firmware gốc */
  char originalFirmware[] = "Original ECU Firmware v1.0 - Signed by OEM";

  /* Firmware bị corrupt (đổi 'O' thành '0') */
  char corruptedFirmware[] = "0riginal ECU Firmware v1.0 - Signed by OEM";

  printf("\n[TÌNH HUỐNG]\n");
  printf("  - Firmware bị corrupt do lỗi Flash hoặc attack\n");
  printf("  - Chỉ 1 byte bị thay đổi: 'O' → '0'\n");

  printf("\n  Original: \"%s\"\n", originalFirmware);
  printf("  Corrupted: \"%s\"\n", corruptedFirmware);
  printf("              ^ (byte khác nhau)\n");

  /* Hash original */
  uint8 hashOriginal[CRYPTO_SHA256_DIGEST_SIZE];
  uint32 len = sizeof(hashOriginal);
  Crypto_SHA256_Calculate((const uint8 *)originalFirmware,
                          (uint32)strlen(originalFirmware), hashOriginal, &len);

  /* Hash corrupted */
  uint8 hashCorrupted[CRYPTO_SHA256_DIGEST_SIZE];
  len = sizeof(hashCorrupted);
  Crypto_SHA256_Calculate((const uint8 *)corruptedFirmware,
                          (uint32)strlen(corruptedFirmware), hashCorrupted,
                          &len);

  printf("\n[SO SÁNH HASH]\n");
  PrintDigest("  Original Hash:  ", hashOriginal, CRYPTO_SHA256_DIGEST_SIZE);
  PrintDigest("  Corrupted Hash: ", hashCorrupted, CRYPTO_SHA256_DIGEST_SIZE);

  /* Đếm bits khác nhau */
  int diffBits = 0;
  for (int i = 0; i < 32; i++) {
    uint8 xorVal = hashOriginal[i] ^ hashCorrupted[i];
    for (int b = 0; b < 8; b++) {
      if (xorVal & (1 << b))
        diffBits++;
    }
  }

  printf("\n[PHÂN TÍCH]\n");
  printf("  - Số bits khác nhau: %d / 256 (%.1f%%)\n", diffBits,
         diffBits * 100.0 / 256);
  printf("  - Dù chỉ 1 byte thay đổi, ~50%% hash bits khác nhau\n");
  printf("  - Không thể giả mạo firmware để có cùng hash!\n");

  printf("\n[KẾT LUẬN]\n");
  if (!CompareDigests(hashOriginal, hashCorrupted, CRYPTO_SHA256_DIGEST_SIZE)) {
    printf("  ✓ Corruption ĐÃ ĐƯỢC PHÁT HIỆN!\n");
    printf("  → Bootloader sẽ reject firmware này\n");
  }
}

/*===========================================================================*/
/*                    MAIN                                                    */
/*===========================================================================*/
int main(void) {
  printf("\n");
  printf("████████████████████████████████████████████████████████████████\n");
  printf("█       HALA ACADEMY - SHA-256 STREAMING EXAMPLES              █\n");
  printf("████████████████████████████████████████████████████████████████\n");

  Example_StreamingBasic();
  Example_FirmwareVerification();
  Example_CorruptedFirmware();

  printf("\n");
  printf("████████████████████████████████████████████████████████████████\n");
  printf("█                        HOÀN TẤT                              █\n");
  printf("████████████████████████████████████████████████████████████████\n");
  printf("\n");

  return 0;
}
