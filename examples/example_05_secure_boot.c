/*******************************************************************************
 * @file    example_05_secure_boot.c
 * @brief   Ví dụ 5: Secure Boot Simulation - Mô phỏng quy trình boot an toàn
 *
 * @author  HALA Academy
 * @version 1.0.0
 * @date    2026-01-02
 *
 * @note    VÍ DỤ NÀY MINH HỌA:
 *          1. Quy trình Secure Boot hoàn chỉnh
 *          2. OEM signing firmware
 *          3. ECU verification khi boot
 *          4. Xử lý các tình huống lỗi
 *          5. Chain of Trust concept
 *
 * @compile gcc -o example_05 example_05_secure_boot.c \
 *              ../src/Crypto_ECDSA.c ../src/Crypto_SHA256.c \
 *              ../lib/micro-ecc/uECC.c \
 *              -I../include -I../lib/micro-ecc -Wall
 * @run     ./example_05
 ******************************************************************************/

#include "Crypto_ECDSA.h"
#include "Crypto_SHA256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*===========================================================================*/
/*                    DATA STRUCTURES                                         */
/*===========================================================================*/

/**
 * @brief Structure mô phỏng firmware image
 */
typedef struct {
  char name[64];           /**< Tên firmware */
  char version[16];        /**< Phiên bản */
  uint8 *data;             /**< Binary data */
  uint32 dataSize;         /**< Kích thước data */
  uint8 signature[64];     /**< ECDSA signature */
  uint8 signerPubKeyX[32]; /**< Public key của signer */
  uint8 signerPubKeyY[32]; /**< Public key của signer */
} FirmwareImage;

/**
 * @brief Structure mô phỏng OTP memory (One-Time Programmable)
 * @note  Trong ECU thực, đây là vùng nhớ chỉ ghi 1 lần, không thể sửa
 */
typedef struct {
  uint8 trustedPubKeyX[32]; /**< Trusted public key X (OEM root key) */
  uint8 trustedPubKeyY[32]; /**< Trusted public key Y */
  bool isProvisioned;       /**< Đã được provision? */
} OTP_Memory;

/**
 * @brief Boot status codes
 */
typedef enum {
  BOOT_OK = 0,
  BOOT_ERR_NO_FIRMWARE = 1,
  BOOT_ERR_OTP_NOT_PROGRAMMED = 2,
  BOOT_ERR_SIGNATURE_INVALID = 3,
  BOOT_ERR_KEY_MISMATCH = 4,
  BOOT_ERR_CORRUPT = 5
} BootStatus;

/*===========================================================================*/
/*                    GLOBAL SIMULATION STATE                                 */
/*===========================================================================*/

static OTP_Memory g_otpMemory;                /* ECU OTP */
static FirmwareImage g_flashFirmware;         /* Firmware trong Flash */
static Crypto_ECDSA_KeyPairType g_oemKeyPair; /* OEM master key */

/*===========================================================================*/
/*                    HELPER FUNCTIONS                                        */
/*===========================================================================*/
static void PrintHex(const char *label, const uint8 *data, uint32 length) {
  printf("%s", label);
  for (uint32 i = 0; i < length; i++) {
    printf("%02x", data[i]);
    if ((i + 1) % 32 == 0 && i < length - 1)
      printf("\n%*s", (int)strlen(label), "");
  }
  printf("\n");
}

static void PrintStatus(const char *step, int success) {
  printf("  [%s] %s\n", success ? "✓" : "✗", step);
}

static void PrintHeader(const char *title) {
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║  %-60s║\n", title);
  printf("╚══════════════════════════════════════════════════════════════╝\n");
}

/*===========================================================================*/
/*                    PHASE 1: OEM MANUFACTURING                              */
/*===========================================================================*/
/**
 * @brief   Mô phỏng quá trình OEM tạo key và provision ECU
 *
 * @details QUY TRÌNH THỰC TẾ:
 *          1. OEM tạo master key pair trong HSM tại nhà máy
 *          2. Private key NEVER leaves HSM
 *          3. Public key được ghi vào OTP của từng ECU
 *          4. ECU được ship với public key đã provision
 */
static void Phase1_OEM_Manufacturing(void) {
  PrintHeader("PHASE 1: OEM MANUFACTURING (NHÀ MÁY)");

  printf("\n  [1.1] OEM tạo Master Key Pair\n");
  printf("  ═══════════════════════════════\n");
  printf("  Địa điểm: HSM tại nhà máy OEM\n");
  printf("  Mục đích: Key này sẽ ký TẤT CẢ firmware releases\n\n");

  Crypto_ECDSA_GenerateKeyPair(&g_oemKeyPair);

  PrintHex("  OEM Private Key: ", g_oemKeyPair.privateKey, 32);
  printf("  ⚠ LƯU TRONG HSM - KHÔNG BAO GIỜ EXPORT!\n\n");

  PrintHex("  OEM Public Key X: ", g_oemKeyPair.publicKeyX, 32);
  PrintHex("  OEM Public Key Y: ", g_oemKeyPair.publicKeyY, 32);

  printf("\n  [1.2] Provision ECU với OEM Public Key\n");
  printf("  ════════════════════════════════════════\n");
  printf("  Địa điểm: Production line, trước khi ship ECU\n");
  printf("  Phương pháp: Ghi vào OTP memory (không thể thay đổi)\n\n");

  memcpy(g_otpMemory.trustedPubKeyX, g_oemKeyPair.publicKeyX, 32);
  memcpy(g_otpMemory.trustedPubKeyY, g_oemKeyPair.publicKeyY, 32);
  g_otpMemory.isProvisioned = true;

  PrintStatus("OTP_WriteTrustedKey(publicKey)", 1);
  PrintStatus("OTP_Lock() - không thể ghi thêm", 1);

  printf("\n  ✓ ECU đã được provision, sẵn sàng ship!\n");
}

/*===========================================================================*/
/*                    PHASE 2: OEM FIRMWARE DEVELOPMENT                       */
/*===========================================================================*/
/**
 * @brief   Mô phỏng quá trình OEM phát triển và ký firmware
 */
static void Phase2_OEM_FirmwareDevelopment(void) {
  PrintHeader("PHASE 2: OEM PHÁT TRIỂN FIRMWARE");

  printf("\n  [2.1] Biên dịch Firmware\n");
  printf("  ══════════════════════════\n");
  printf("  Địa điểm: OEM Development Lab\n\n");

  /* Mô phỏng firmware binary */
  static char firmwareData[] = "/* ECU Firmware v3.2.1 - Application Code */\n"
                               "void main(void) {\n"
                               "    CAN_Init();\n"
                               "    Crypto_Init();\n"
                               "    while(1) {\n"
                               "        ProcessMessages();\n"
                               "        UpdateActuators();\n"
                               "        WatchdogFeed();\n"
                               "    }\n"
                               "}\n"
                               "/* Calibration Data: [0x1234, 0x5678, ...] */\n"
                               "/* CRC32: 0xDEADBEEF */\n";

  strcpy(g_flashFirmware.name, "ECU_APPLICATION");
  strcpy(g_flashFirmware.version, "v3.2.1");
  g_flashFirmware.data = (uint8 *)firmwareData;
  g_flashFirmware.dataSize = strlen(firmwareData);

  printf("  Firmware: %s %s\n", g_flashFirmware.name, g_flashFirmware.version);
  printf("  Size: %u bytes\n", g_flashFirmware.dataSize);
  printf("  Content preview:\n");
  printf("  ┌────────────────────────────────────────────────────────────┐\n");

  /* In một phần firmware */
  for (int i = 0; i < 5 && i < 10; i++) {
    char line[61];
    int start = i * 50;
    int len = 50;
    if (start + len > (int)g_flashFirmware.dataSize) {
      len = g_flashFirmware.dataSize - start;
    }
    if (len <= 0)
      break;
    strncpy(line, (char *)g_flashFirmware.data + start, len);
    line[len] = '\0';
    /* Remove newlines for display */
    for (int j = 0; j < len; j++) {
      if (line[j] == '\n')
        line[j] = ' ';
    }
    printf("  │ %-58s │\n", line);
  }
  printf("  │ ...                                                        │\n");
  printf("  └────────────────────────────────────────────────────────────┘\n");

  printf("\n  [2.2] Ký Firmware bằng OEM Private Key\n");
  printf("  ════════════════════════════════════════\n");
  printf("  Địa điểm: HSM-connected Signing Server\n");
  printf("  Quy trình:\n");
  printf("    1. Hash firmware bằng SHA-256\n");
  printf("    2. Sign hash bằng ECDSA với private key trong HSM\n");
  printf("    3. Attach signature vào firmware package\n\n");

  /* Hash firmware */
  uint8 digest[32];
  uint32 digestLen = 32;
  Crypto_SHA256_Calculate(g_flashFirmware.data, g_flashFirmware.dataSize,
                          digest, &digestLen);

  PrintHex("  Firmware Hash: ", digest, 32);

  /* Sign */
  Crypto_ECDSA_SetPrivateKey(KEY_SLOT_SIGN, g_oemKeyPair.privateKey, 32);

  uint32 sigLen = 64;
  Crypto_ECDSA_Sign(KEY_SLOT_SIGN, digest, 32, g_flashFirmware.signature,
                    &sigLen);

  PrintHex("  Signature R: ", g_flashFirmware.signature, 32);
  PrintHex("  Signature S: ", g_flashFirmware.signature + 32, 32);

  /* Copy signer's public key */
  memcpy(g_flashFirmware.signerPubKeyX, g_oemKeyPair.publicKeyX, 32);
  memcpy(g_flashFirmware.signerPubKeyY, g_oemKeyPair.publicKeyY, 32);

  printf("\n  ✓ Firmware đã được ký, sẵn sàng deploy!\n");
}

/*===========================================================================*/
/*                    PHASE 3: ECU SECURE BOOT                                */
/*===========================================================================*/
/**
 * @brief   Mô phỏng quy trình Secure Boot khi ECU khởi động
 *
 * @return  BootStatus
 */
static BootStatus Phase3_ECU_SecureBoot(void) {
  PrintHeader("PHASE 3: ECU SECURE BOOT");

  printf(
      "\n  ┌────────────────────────────────────────────────────────────┐\n");
  printf("  │  ECU POWER ON → BOOTLOADER STARTS                         │\n");
  printf("  └────────────────────────────────────────────────────────────┘\n");

  printf("\n  [3.1] Kiểm tra OTP Memory\n");
  printf("  ══════════════════════════\n");

  if (!g_otpMemory.isProvisioned) {
    PrintStatus("OTP chưa được provision!", 0);
    return BOOT_ERR_OTP_NOT_PROGRAMMED;
  }
  PrintStatus("OTP đã được provision với trusted key", 1);

  printf("\n  [3.2] Load Trusted Public Key từ OTP\n");
  printf("  ══════════════════════════════════════\n");

  PrintHex("  Trusted Key X: ", g_otpMemory.trustedPubKeyX, 32);
  PrintHex("  Trusted Key Y: ", g_otpMemory.trustedPubKeyY, 32);
  PrintStatus("Trusted key loaded", 1);

  printf("\n  [3.3] Đọc Firmware từ Flash\n");
  printf("  ════════════════════════════\n");

  if (g_flashFirmware.dataSize == 0) {
    PrintStatus("Không có firmware trong Flash!", 0);
    return BOOT_ERR_NO_FIRMWARE;
  }

  printf("  Firmware: %s %s (%u bytes)\n", g_flashFirmware.name,
         g_flashFirmware.version, g_flashFirmware.dataSize);
  PrintStatus("Firmware loaded", 1);

  printf("\n  [3.4] Verify Signer Key vs Trusted Key\n");
  printf("  ════════════════════════════════════════\n");
  printf("  Kiểm tra firmware được ký bởi OEM (không phải attacker)\n\n");

  int keyMatch = (memcmp(g_flashFirmware.signerPubKeyX,
                         g_otpMemory.trustedPubKeyX, 32) == 0) &&
                 (memcmp(g_flashFirmware.signerPubKeyY,
                         g_otpMemory.trustedPubKeyY, 32) == 0);

  if (!keyMatch) {
    PrintStatus("Signer key KHÔNG KHỚP với trusted key!", 0);
    printf("  ⚠ Firmware có thể được ký bởi attacker!\n");
    return BOOT_ERR_KEY_MISMATCH;
  }
  PrintStatus("Signer key khớp với OEM trusted key", 1);

  printf("\n  [3.5] Hash Firmware (Streaming Mode)\n");
  printf("  ══════════════════════════════════════\n");
  printf("  Sử dụng SHA-256 streaming vì RAM hạn chế\n\n");

  Crypto_SHA256_ContextType ctx;
  uint8 calculatedHash[32];
  uint32 hashLen = 32;

  Crypto_SHA256_Init(&ctx);

  /* Giả lập hash từng page */
  uint32 pageSize = 64;
  uint32 offset = 0;
  int pageNum = 0;

  while (offset < g_flashFirmware.dataSize) {
    uint32 chunkLen = pageSize;
    if (offset + chunkLen > g_flashFirmware.dataSize) {
      chunkLen = g_flashFirmware.dataSize - offset;
    }

    Crypto_SHA256_Update(&ctx, g_flashFirmware.data + offset, chunkLen);
    printf("  Page %d: offset %u, size %u bytes → hashed\n", pageNum, offset,
           chunkLen);

    offset += chunkLen;
    pageNum++;
  }

  Crypto_SHA256_Finish(&ctx, calculatedHash, &hashLen);

  PrintHex("\n  Calculated Hash: ", calculatedHash, 32);
  PrintStatus("Hash completed", 1);

  printf("\n  [3.6] Verify Signature\n");
  printf("  ═══════════════════════\n");

  Crypto_ECDSA_SetPublicKey(KEY_SLOT_VERIFY, g_otpMemory.trustedPubKeyX,
                            g_otpMemory.trustedPubKeyY, 32);

  Crypto_VerifyResultType verifyResult;
  Crypto_ECDSA_Verify(KEY_SLOT_VERIFY, calculatedHash, 32,
                      g_flashFirmware.signature, 64, &verifyResult);

  if (verifyResult != CRYPTO_E_VER_OK) {
    PrintStatus("SIGNATURE KHÔNG HỢP LỆ!", 0);
    printf("\n  ╔════════════════════════════════════════════════════════╗\n");
    printf("  ║  ⚠ BOOT ABORTED - POSSIBLE ATTACK OR CORRUPTION        ║\n");
    printf("  ╚════════════════════════════════════════════════════════╝\n");
    return BOOT_ERR_SIGNATURE_INVALID;
  }

  PrintStatus("SIGNATURE HỢP LỆ!", 1);

  printf("\n  [3.7] Boot Application\n");
  printf("  ═══════════════════════\n");

  printf(
      "\n  ╔════════════════════════════════════════════════════════════╗\n");
  printf("  ║                                                            ║\n");
  printf("  ║     ✓ SECURE BOOT SUCCESSFUL                              ║\n");
  printf("  ║                                                            ║\n");
  printf("  ║     Firmware: %s %-36s║\n", g_flashFirmware.name,
         g_flashFirmware.version);
  printf("  ║     Status:   VERIFIED & TRUSTED                          ║\n");
  printf("  ║     Action:   Jumping to application...                   ║\n");
  printf("  ║                                                            ║\n");
  printf("  ╚════════════════════════════════════════════════════════════╝\n");

  return BOOT_OK;
}

/*===========================================================================*/
/*                    PHASE 4: ATTACK SIMULATION                              */
/*===========================================================================*/
/**
 * @brief   Mô phỏng các loại tấn công và cách phát hiện
 */
static void Phase4_AttackSimulation(void) {
  PrintHeader("PHASE 4: MÔ PHỎNG TẤN CÔNG");

  printf("\n  Lưu lại firmware gốc...\n");
  FirmwareImage originalFirmware;
  memcpy(&originalFirmware, &g_flashFirmware, sizeof(FirmwareImage));

  /*=======================================================================
   * Attack 1: Sửa firmware nhưng giữ signature
   *=======================================================================*/
  printf(
      "\n  ┌────────────────────────────────────────────────────────────┐\n");
  printf("  │  ATTACK 1: Sửa firmware, giữ signature gốc                 │\n");
  printf("  └────────────────────────────────────────────────────────────┘\n");

  printf("\n  Attacker thay đổi firmware code...\n");
  static char malwareData[] = "MALWARE_PAYLOAD: steal_keys(); brick_ecu();";
  g_flashFirmware.data = (uint8 *)malwareData;
  g_flashFirmware.dataSize = strlen(malwareData);

  printf("  Thử boot với firmware đã bị sửa...\n");

  BootStatus status1 = Phase3_ECU_SecureBoot();

  printf("\n  Kết quả Attack 1: %s\n", (status1 == BOOT_ERR_SIGNATURE_INVALID)
                                           ? "✓ DETECTED & BLOCKED!"
                                           : "✗ Attack succeeded (BUG!)");

  /* Restore */
  memcpy(&g_flashFirmware, &originalFirmware, sizeof(FirmwareImage));

  /*=======================================================================
   * Attack 2: Ký bằng key khác (attacker's key)
   *=======================================================================*/
  printf(
      "\n  ┌────────────────────────────────────────────────────────────┐\n");
  printf("  │  ATTACK 2: Ký firmware bằng attacker's key                 │\n");
  printf("  └────────────────────────────────────────────────────────────┘\n");

  printf("\n  Attacker tạo key pair riêng...\n");
  Crypto_ECDSA_KeyPairType attackerKey;
  Crypto_ECDSA_GenerateKeyPair(&attackerKey);

  printf("  Attacker ký malware bằng key của attacker...\n");

  /* Sign with attacker's key */
  Crypto_ECDSA_SetPrivateKey(KEY_SLOT_SIGN, attackerKey.privateKey, 32);

  uint8 digest[32];
  uint32 digestLen = 32;
  Crypto_SHA256_Calculate(g_flashFirmware.data, g_flashFirmware.dataSize,
                          digest, &digestLen);

  uint32 sigLen = 64;
  Crypto_ECDSA_Sign(KEY_SLOT_SIGN, digest, 32, g_flashFirmware.signature,
                    &sigLen);

  /* Update signer's public key (attacker's) */
  memcpy(g_flashFirmware.signerPubKeyX, attackerKey.publicKeyX, 32);
  memcpy(g_flashFirmware.signerPubKeyY, attackerKey.publicKeyY, 32);

  printf("  Thử boot với firmware ký bởi attacker...\n");

  BootStatus status2 = Phase3_ECU_SecureBoot();

  printf("\n  Kết quả Attack 2: %s\n", (status2 == BOOT_ERR_KEY_MISMATCH)
                                           ? "✓ DETECTED & BLOCKED!"
                                           : "✗ Attack succeeded (BUG!)");

  /* Restore */
  memcpy(&g_flashFirmware, &originalFirmware, sizeof(FirmwareImage));

  printf("\n  ✓ Tất cả các attack đã bị phát hiện và chặn!\n");
}

/*===========================================================================*/
/*                    MAIN                                                    */
/*===========================================================================*/
int main(void) {
  printf("\n");
  printf("████████████████████████████████████████████████████████████████\n");
  printf("█       HALA ACADEMY - SECURE BOOT SIMULATION                  █\n");
  printf("████████████████████████████████████████████████████████████████\n");

  printf("\n");
  printf("  ╔════════════════════════════════════════════════════════════╗\n");
  printf("  ║                   CHAIN OF TRUST                           ║\n");
  printf("  ╠════════════════════════════════════════════════════════════╣\n");
  printf("  ║                                                            ║\n");
  printf("  ║   OEM HSM ──────────────────────────────────────────┐      ║\n");
  printf("  ║      │                                              │      ║\n");
  printf("  ║      │ Private Key (never leaves HSM)               │      ║\n");
  printf("  ║      │                                              │      ║\n");
  printf("  ║      ├──► Signs Firmware ──────────────────────┐    │      ║\n");
  printf("  ║      │                                         │    │      ║\n");
  printf("  ║      └──► Public Key ─────────┐                │    │      ║\n");
  printf("  ║                               │                │    │      ║\n");
  printf("  ║                               ▼                ▼    │      ║\n");
  printf("  ║   ECU: [ OTP: Trusted Key ]  ───► Verifies Signature      ║\n");
  printf("  ║                                              │             ║\n");
  printf("  ║                                              ▼             ║\n");
  printf("  ║                                   ✓ Boot if valid          ║\n");
  printf("  ║                                   ✗ Reject if invalid      ║\n");
  printf("  ║                                                            ║\n");
  printf("  ╚════════════════════════════════════════════════════════════╝\n");

  /* Execute phases */
  Phase1_OEM_Manufacturing();
  Phase2_OEM_FirmwareDevelopment();
  Phase3_ECU_SecureBoot();
  Phase4_AttackSimulation();

  printf("\n");
  printf("████████████████████████████████████████████████████████████████\n");
  printf("█                     SIMULATION HOÀN TẤT                      █\n");
  printf("████████████████████████████████████████████████████████████████\n");
  printf("\n");
  printf("  Kiến thức đã học:\n");
  printf("  ─────────────────\n");
  printf("  1. OEM provision ECU với trusted public key trong OTP\n");
  printf("  2. OEM ký firmware bằng private key (trong HSM)\n");
  printf("  3. ECU verify firmware bằng trusted public key\n");
  printf("  4. Attacker không thể:\n");
  printf("     - Sửa firmware mà không bị phát hiện\n");
  printf("     - Ký firmware vì không có OEM private key\n");
  printf("     - Thay trusted key vì OTP đã lock\n");
  printf("\n");

  return 0;
}
