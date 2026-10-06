/*******************************************************************************
 * @file    main.c
 * @brief   Demo Application - SHA-256 + ECDSA Digital Signature
 * @details Minh họa cách sử dụng Crypto Stack theo phong cách AUTOSAR Classic
 *
 * @note    CÁC VÍ DỤ TRONG FILE NÀY:
 *
 *          1. SHA-256 Single Call: Hash chuỗi ngắn, so sánh với FIPS test
 *vector
 *          2. SHA-256 Streaming: Hash dữ liệu lớn theo chunks (mô phỏng
 *firmware)
 *          3. ECDSA Key Generation: Tạo cặp Private/Public key
 *          4. ECDSA Sign & Verify: Ký và xác thực message
 *          5. Tamper Detection: Phát hiện message bị sửa đổi
 ******************************************************************************/

/*===========================================================================*/
/*                              INCLUDES                                      */
/*===========================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Crypto_ECDSA.h"
#include "Crypto_SHA256.h"

/*===========================================================================*/
/*                    HELPER FUNCTIONS                                        */
/*===========================================================================*/

/**
 * @brief   In mảng bytes dưới dạng hex
 *
 * @param[in] prefix  Chuỗi prefix trước khi in
 * @param[in] data    Data cần in
 * @param[in] length  Độ dài data
 */
static void PrintHex(const char *prefix, const uint8 *data, uint32 length)
{
  uint32 i;

  printf("%s", prefix);
  for (i = 0u; i < length; i++)
  {
    printf("%02x", data[i]);
  }
  printf("\n");
}

/**
 * @brief   In dòng kẻ phân cách
 */
static void PrintSeparator(void)
{
  printf("\n");
  printf("================================================================\n");
}

/**
 * @brief   So sánh 2 mảng bytes
 *
 * @param[in] a       Mảng thứ nhất
 * @param[in] b       Mảng thứ hai
 * @param[in] length  Độ dài cần so sánh
 *
 * @return  true nếu khớp, false nếu không khớp
 */
static bool CompareBytes(const uint8 *a, const uint8 *b, uint32 length)
{
  uint32 i;

  for (i = 0u; i < length; i++)
  {
    if (a[i] != b[i])
    {
      return false;
    }
  }
  return true;
}

/**
 * @brief   Chuyển hex string sang bytes
 *
 * @param[in]  hexStr  Chuỗi hex
 * @param[out] bytes   Buffer output
 * @param[in]  length  Độ dài bytes cần chuyển
 */
static void HexToBytes(const char *hexStr, uint8 *bytes, uint32 length)
{
  uint32 i;

  for (i = 0u; i < length; i++)
  {
    sscanf(&hexStr[i * 2u], "%2hhx", &bytes[i]);
  }
}

/*===========================================================================*/
/*              VÍ DỤ 1: SHA-256 SINGLE CALL                                  */
/*===========================================================================*/
/**
 * @brief   Demo hash đơn giản với FIPS 180-4 test vector
 *
 * @details Test vector từ FIPS 180-4:
 *          - Input: "abc"
 *          - Expected: ba7816bf8f01cfea414140de5dae2223
 *                      b00361a396177a9cb410ff61f20015ad
 */
static void Example_SHA256_SingleCall(void)
{
  const char *message = "abc";
  uint8 digest[CRYPTO_SHA256_DIGEST_SIZE];
  uint32 digestLen = sizeof(digest);

  /* Expected digest từ FIPS 180-4 */
  const char *expectedHex = "ba7816bf8f01cfea414140de5dae2223"
                            "b00361a396177a9cb410ff61f20015ad";
  uint8 expected[CRYPTO_SHA256_DIGEST_SIZE];

  PrintSeparator();
  printf("VÍ DỤ 1: SHA-256 SINGLE CALL (FIPS 180-4 Test Vector)\n");
  PrintSeparator();

  printf("\nInput message: \"%s\" (3 bytes)\n", message);

  /*-----------------------------------------------------------------------
   * Gọi CSM API để hash
   *-----------------------------------------------------------------------*/
  Std_ReturnType result = Csm_Hash(
      JOB_ID_HASH_SHA256, CRYPTO_OPERATIONMODE_SINGLECALL,
      (const uint8 *)message, (uint32)strlen(message), digest, &digestLen);

  if (result == E_OK)
  {
    printf("\n✓ Hash thành công!\n\n");
    PrintHex("Calculated: ", digest, digestLen);
    printf("Expected:   %s\n", expectedHex);

    /* Verify kết quả */
    HexToBytes(expectedHex, expected, CRYPTO_SHA256_DIGEST_SIZE);

    if (CompareBytes(digest, expected, CRYPTO_SHA256_DIGEST_SIZE))
    {
      printf("\n✓ KẾT QUẢ KHỚP VỚI FIPS 180-4 TEST VECTOR!\n");
    }
    else
    {
      printf("\n✗ KẾT QUẢ KHÔNG KHỚP!\n");
    }
  }
  else
  {
    printf("\n✗ Hash thất bại! Error code: %d\n", result);
  }
}

/*===========================================================================*/
/*              VÍ DỤ 2: SHA-256 STREAMING                                    */
/*===========================================================================*/
/**
 * @brief   Demo hash streaming (dữ liệu lớn theo chunks)
 *
 * @details Mô phỏng tình huống thực tế: hash firmware nhiều MB
 *          nhưng ECU chỉ có RAM nhỏ, phải xử lý từng chunk.
 */
static void Example_SHA256_Streaming(void)
{
  /* Mô phỏng firmware được chia thành 3 chunks */
  const char *chunk1 = "Firmware Header: HALA ECU v2.1.0 Build 2026.01.02";
  const char *chunk2 =
      "[.text section: boot code, main loop, interrupt handlers...]";
  const char *chunk3 =
      "[.data section: configuration, calibration data...] CRC:OK";

  uint8 digestStreaming[CRYPTO_SHA256_DIGEST_SIZE];
  uint8 digestSingleCall[CRYPTO_SHA256_DIGEST_SIZE];
  uint32 digestLen;

  PrintSeparator();
  printf("VÍ DỤ 2: SHA-256 STREAMING MODE (Firmware Verification)\n");
  PrintSeparator();

  printf("\nMô phỏng hash firmware lớn theo chunks:\n");
  printf("  Chunk 1: \"%s\"\n", chunk1);
  printf("  Chunk 2: \"%s\"\n", chunk2);
  printf("  Chunk 3: \"%s\"\n", chunk3);

  /*-----------------------------------------------------------------------
   * STREAMING MODE: START → UPDATE (nhiều lần) → FINISH
   *-----------------------------------------------------------------------*/
  printf("\n--- Streaming Mode ---\n");

  /* START: Khởi tạo context */
  Csm_Hash(JOB_ID_HASH_SHA256, CRYPTO_OPERATIONMODE_START, NULL, 0, NULL, NULL);
  printf("  START:  Khởi tạo context\n");

  /* UPDATE: Thêm chunk 1 */
  Csm_Hash(JOB_ID_HASH_SHA256, CRYPTO_OPERATIONMODE_UPDATE,
           (const uint8 *)chunk1, (uint32)strlen(chunk1), NULL, NULL);
  printf("  UPDATE: Đã thêm chunk 1 (%zu bytes)\n", strlen(chunk1));

  /* UPDATE: Thêm chunk 2 */
  Csm_Hash(JOB_ID_HASH_SHA256, CRYPTO_OPERATIONMODE_UPDATE,
           (const uint8 *)chunk2, (uint32)strlen(chunk2), NULL, NULL);
  printf("  UPDATE: Đã thêm chunk 2 (%zu bytes)\n", strlen(chunk2));

  /* UPDATE: Thêm chunk 3 */
  Csm_Hash(JOB_ID_HASH_SHA256, CRYPTO_OPERATIONMODE_UPDATE,
           (const uint8 *)chunk3, (uint32)strlen(chunk3), NULL, NULL);
  printf("  UPDATE: Đã thêm chunk 3 (%zu bytes)\n", strlen(chunk3));

  /* FINISH: Kết thúc và lấy digest (không truyền data) */
  digestLen = sizeof(digestStreaming);
  Csm_Hash(JOB_ID_HASH_SHA256, CRYPTO_OPERATIONMODE_FINISH, NULL, 0,
           digestStreaming, &digestLen);
  printf("  FINISH: Kết thúc và lấy digest\n");

  PrintHex("\nStreaming Hash: ", digestStreaming, digestLen);

  /*-----------------------------------------------------------------------
   * SO SÁNH: Hash toàn bộ message ghép lại
   *-----------------------------------------------------------------------*/
  printf("\n--- Single Call (để verify) ---\n");

  /* Ghép tất cả chunks */
  char fullMessage[512];
  strcpy(fullMessage, chunk1);
  strcat(fullMessage, chunk2);
  strcat(fullMessage, chunk3);

  digestLen = sizeof(digestSingleCall);
  Csm_Hash(JOB_ID_HASH_SHA256, CRYPTO_OPERATIONMODE_SINGLECALL,
           (const uint8 *)fullMessage, (uint32)strlen(fullMessage),
           digestSingleCall, &digestLen);

  PrintHex("SingleCall Hash: ", digestSingleCall, digestLen);

  /* Verify 2 kết quả khớp nhau */
  if (CompareBytes(digestStreaming, digestSingleCall,
                   CRYPTO_SHA256_DIGEST_SIZE))
  {
    printf("\n✓ STREAMING VÀ SINGLE CALL CHO CÙNG KẾT QUẢ!\n");
    printf("  → Streaming mode hoạt động đúng\n");
  }
  else
  {
    printf("\n✗ KẾT QUẢ KHÔNG KHỚP!\n");
  }
}

/*===========================================================================*/
/*              VÍ DỤ 3: ECDSA KEY GENERATION & SIGN/VERIFY                   */
/*===========================================================================*/
/**
 * @brief   Demo ECDSA: Tạo key, ký, và xác thực
 *
 * @details Mô phỏng flow Secure Boot / Message Authentication:
 *          1. OEM tạo key pair
 *          2. OEM ký firmware/message bằng private key
 *          3. ECU verify bằng public key (đã được provisioned)
 */
static void Example_ECDSA_SignAndVerify(void)
{
  Crypto_ECDSA_KeyPairType keyPair;
  const char *message = "ECU Firmware v2.1.0 - Official HALA Release";
  uint8 signature[CRYPTO_ECDSA_P256_SIG_SIZE];
  uint32 sigLen = sizeof(signature);
  Std_ReturnType result;
  Crypto_VerifyResultType verifyResult;

  PrintSeparator();
  printf("VÍ DỤ 3: ECDSA P-256 DIGITAL SIGNATURE\n");
  PrintSeparator();

  /*-----------------------------------------------------------------------
   * BƯỚC 1: TẠO KEY PAIR
   *
   * Trong thực tế: Thực hiện 1 lần khi provision ECU
   * Private key lưu tại OEM (signing server)
   * Public key nhúng vào ECU (bootloader)
   *-----------------------------------------------------------------------*/
  printf("\n[1] TẠO KEY PAIR (ECDSA P-256)\n");
  printf("    ─────────────────────────\n");

  result = Crypto_ECDSA_GenerateKeyPair(&keyPair);

  if (result == E_OK)
  {
    printf("    ✓ Key pair đã được tạo!\n\n");

    PrintHex("    Private Key (BÍ MẬT!): ", keyPair.privateKey,
             CRYPTO_ECDSA_P256_KEY_SIZE);
    PrintHex("    Public Key X:          ", keyPair.publicKeyX,
             CRYPTO_ECDSA_P256_KEY_SIZE);
    PrintHex("    Public Key Y:          ", keyPair.publicKeyY,
             CRYPTO_ECDSA_P256_KEY_SIZE);
  }
  else
  {
    printf("    ✗ Tạo key thất bại!\n");
    return;
  }

  /*-----------------------------------------------------------------------
   * BƯỚC 2: SET KEYS VÀO CRYPTO DRIVER
   *-----------------------------------------------------------------------*/
  printf("\n[2] NẠP KEYS VÀO CRYPTO DRIVER\n");
  printf("    ──────────────────────────\n");

  /* Private key cho signing */
  Csm_KeyElementSet_PrivateKey(KEY_SLOT_SIGN, keyPair.privateKey,
                               CRYPTO_ECDSA_P256_KEY_SIZE);
  printf("    ✓ Private key đã nạp vào slot SIGN\n");

  /* Public key cho verification */
  Csm_KeyElementSet_PublicKey(KEY_SLOT_VERIFY, keyPair.publicKeyX,
                              keyPair.publicKeyY, CRYPTO_ECDSA_P256_KEY_SIZE);
  printf("    ✓ Public key đã nạp vào slot VERIFY\n");

  /*-----------------------------------------------------------------------
   * BƯỚC 3: KÝ MESSAGE (phía OEM/Signing Server)
   *
   * CSM tự động: Hash(message) → Sign(hash) → Signature
   *-----------------------------------------------------------------------*/
  printf("\n[3] TẠO CHỮ KÝ SỐ\n");
  printf("    ──────────────\n");
  printf("    Message: \"%s\"\n", message);

  sigLen = sizeof(signature);
  result = Csm_SignatureGenerate(JOB_ID_SIGN, CRYPTO_OPERATIONMODE_SINGLECALL,
                                 (const uint8 *)message,
                                 (uint32)strlen(message), signature, &sigLen);

  if (result == E_OK)
  {
    printf("\n    ✓ Signature tạo thành công!\n\n");
    PrintHex("    Signature R: ", signature, 32);
    PrintHex("    Signature S: ", signature + 32, 32);
  }
  else
  {
    printf("    ✗ Signing thất bại!\n");
    return;
  }

  /*-----------------------------------------------------------------------
   * BƯỚC 4: VERIFY MESSAGE (phía ECU)
   *
   * CSM tự động: Hash(message) → Verify(hash, signature, publicKey)
   *-----------------------------------------------------------------------*/
  printf("\n[4] XÁC THỰC CHỮ KÝ (BÊN ECU)\n");
  printf("    ─────────────────────────\n");

  result = Csm_SignatureVerify(JOB_ID_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL,
                               (const uint8 *)message, (uint32)strlen(message),
                               signature, sigLen, &verifyResult);

  if (result == E_OK)
  {
    if (verifyResult == CRYPTO_E_VER_OK)
    {
      printf("    ✓ SIGNATURE HỢP LỆ!\n");
      printf("    → Message chưa bị sửa đổi\n");
      printf("    → Được ký bởi người có private key\n");
    }
    else
    {
      printf("    ✗ SIGNATURE KHÔNG HỢP LỆ!\n");
    }
  }
  else
  {
    printf("    ✗ Verify thất bại!\n");
  }

  /*-----------------------------------------------------------------------
   * BƯỚC 5: TEST - PHÁT HIỆN MESSAGE BỊ SỬA ĐỔI
   *-----------------------------------------------------------------------*/
  printf("\n[5] TEST: PHÁT HIỆN TAMPERING\n");
  printf("    ─────────────────────────\n");

  const char *tamperedMessage = "ECU Firmware v2.1.0 - HACKED Release!!";
  printf("    Tampered: \"%s\"\n", tamperedMessage);

  result = Csm_SignatureVerify(JOB_ID_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL,
                               (const uint8 *)tamperedMessage,
                               (uint32)strlen(tamperedMessage),
                               signature, /* Dùng signature của message gốc */
                               sigLen, &verifyResult);

  if (result == E_OK)
  {
    if (verifyResult == CRYPTO_E_VER_OK)
    {
      printf("\n    ✓ Signature hợp lệ (KHÔNG NÊN XẢY RA!)\n");
    }
    else
    {
      printf("\n    ✗ SIGNATURE KHÔNG HỢP LỆ!\n");
      printf("    → ĐÚNG! Đã phát hiện message bị sửa đổi\n");
      printf("    → Hệ thống từ chối firmware giả mạo\n");
    }
  }
}

/*===========================================================================*/
/*              MAIN FUNCTION                                                 */
/*===========================================================================*/
int main(void)
{
  printf("\n");
  printf("╔══════════════════════════════════════════════════════════════╗\n");
  printf("║       HALA ACADEMY - AUTOSAR CRYPTO STACK DEMO               ║\n");
  printf("║                  SHA-256 + ECDSA P-256                       ║\n");
  printf("╚══════════════════════════════════════════════════════════════╝\n");

  /*-----------------------------------------------------------------------
   * KHỞI TẠO CRYPTO STACK
   *-----------------------------------------------------------------------*/
  printf("\nKhởi tạo Crypto Stack...\n");

  if (Csm_Init() == E_OK)
  {
    printf("✓ CSM đã khởi tạo\n");
  }
  else
  {
    printf("✗ Lỗi khởi tạo CSM!\n");
    return 1;
  }

  /*-----------------------------------------------------------------------
   * CHẠY CÁC VÍ DỤ
   *-----------------------------------------------------------------------*/

  /* Ví dụ 1: SHA-256 Single Call */
  Example_SHA256_SingleCall();

  /* Ví dụ 2: SHA-256 Streaming */
  Example_SHA256_Streaming();

  /* Ví dụ 3: ECDSA Sign & Verify */
  Example_ECDSA_SignAndVerify();

  /*-----------------------------------------------------------------------
   * KẾT THÚC
   *-----------------------------------------------------------------------*/
  PrintSeparator();
  printf("DEMO HOÀN TẤT!\n");
  PrintSeparator();

  printf("\nTÓM TẮT KIẾN TRÚC AUTOSAR CRYPTO STACK:\n");
  printf("  Application → Csm → CryIf → Crypto Driver\n");
  printf("\nAPIs đã demo:\n");
  printf("  - Csm_Hash() với mode SINGLECALL và STREAMING\n");
  printf("  - Csm_SignatureGenerate() - Hash + Sign\n");
  printf("  - Csm_SignatureVerify() - Hash + Verify\n");
  printf("  - Crypto_ECDSA_GenerateKeyPair() - Tạo Private/Public key\n");
  printf("\n");

  return 0;
}
