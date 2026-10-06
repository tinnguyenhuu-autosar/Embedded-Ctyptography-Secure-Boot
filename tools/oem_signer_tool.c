/*******************************************************************************
 * @file    example_07_oem_sign_tool.c
 * @brief   Tool chạy trên máy chủ OEM để ký Firmware
 *
 * @details Mô phỏng máy chủ ở nhà máy sản xuất xe:
 *          1. Tạo cặp key ECDSA P-256
 *          2. Lấy Private Key ký vào Firmware (dùng thuật toán SHA-256 + ECDSA)
 *          3. Xuất ra Public Key và Signature dưới dạng mảng C (C-array)
 *             để copy/paste thẳng vào Source code của ECU (Bootloader)
 *
 *          *Lưu ý: Tool này chạy trên máy tính (Host), không chạy trên ECU.*
 *
 * @author  HALA Academy
 * @version 1.0.0
 ******************************************************************************/

#include "Crypto_ECDSA.h"
#include "Crypto_SHA256.h"
#include <stdio.h>
#include <string.h>

/*===========================================================================*/
/*  HELPER: In mảng byte thành code C                                       */
/*===========================================================================*/
static void Print_C_Array(const char* name, const uint8* data, uint32 len) {
    printf("const uint8 %s[%u] = {\n    ", name, len);
    for(uint32 i = 0; i < len; i++) {
        printf("0x%02X", data[i]);
        if (i < len - 1) printf(", ");
        if ((i + 1) % 8 == 0 && i < len - 1) printf("\n    ");
    }
    printf("\n};\n\n");
}

/*===========================================================================*/
/*  MAIN                                                                     */
/*===========================================================================*/
int main(void) {
    printf("========================================================\n");
    printf("  [OEM SERVER] Ký Firmware chuẩn bị nạp xuống ECU       \n");
    printf("========================================================\n\n");

    /* 1. Dummy Firmware (Data sẽ ghi vào ECU Flash) */
    const char *firmware = "HALA ECU FW v3.0 - Official 2026";
    uint32 fwLen = (uint32)strlen(firmware);

    printf("[1] Noi dung Firmware:\n");
    printf("    \"%s\"\n\n", firmware);

    /* 2. Key Generation */
    printf("[2] Tao ECDSA P-256 Key Pair...\n");
    Crypto_ECDSA_KeyPairType kp;
    if (Crypto_ECDSA_GenerateKeyPair(&kp) != E_OK) {
        printf("Loi tao key!\n");
        return 1;
    }
    printf("    -> Thanh cong (Private Key chi luu tren server)\n\n");

    /* 3. Ký Firmware (Host Tool dùng thẳng driver, không qua CSM) */
    printf("[3] Ky Firmware...\n");
    
    // 3.1 Hash
    uint8 digest[CRYPTO_SHA256_DIGEST_SIZE];
    uint32 digestLen = sizeof(digest);
    Crypto_SHA256_Calculate((const uint8*)firmware, fwLen, digest, &digestLen);

    // 3.2 Nạp Private Key vào khe (mô phỏng driver)
    Crypto_ECDSA_SetPrivateKey(0, kp.privateKey, 32);

    // 3.3 Sign
    uint8 signature[CRYPTO_ECDSA_P256_SIG_SIZE];
    uint32 sigLen = sizeof(signature);
    if (Crypto_ECDSA_Sign(0, digest, digestLen, signature, &sigLen) != E_OK) {
        printf("Loi ky!\n");
        return 1;
    }
    printf("    -> Thanh cong\n\n");

    /* 4. Xuất Code C cho Bootloader */
    printf("========================================================\n");
    printf("  COPY/PASTE ĐOẠN CODE SAU VÀO FIRMWARE CỦA ECU         \n");
    printf("========================================================\n\n");

    printf("/* 1. Firmware Content (Mô phỏng đọc từ Flash) */\n");
    printf("const char* const FIRMWARE_FLASH = \"%s\";\n\n", firmware);

    printf("/* 2. Public Key (Ghi vào OTP/ROM của ECU) */\n");
    uint8 pubKey[64];
    memcpy(pubKey, kp.publicKeyX, 32);
    memcpy(pubKey + 32, kp.publicKeyY, 32);
    Print_C_Array("PUBLIC_KEY_OEM", pubKey, 64);

    printf("/* 3. Signature (Được nạp chung với Firmware vào Flash) */\n");
    Print_C_Array("FIRMWARE_SIGNATURE", signature, 64);

    /* 5. Tạo chữ ký cho UDS Authentication (Case 2) */
    const char *challenge = "ECU_CHALLENGE_001";
    uint32 challengeLen = (uint32)strlen(challenge);
    uint8 chalDigest[CRYPTO_SHA256_DIGEST_SIZE];
    uint32 chalDigestLen = sizeof(chalDigest);
    Crypto_SHA256_Calculate((const uint8*)challenge, challengeLen, chalDigest, &chalDigestLen);

    uint8 chalSignature[CRYPTO_ECDSA_P256_SIG_SIZE];
    uint32 chalSigLen = sizeof(chalSignature);
    Crypto_ECDSA_Sign(0, chalDigest, chalDigestLen, chalSignature, &chalSigLen);

    printf("/* 4. Signature cho UDS Authentication (Dành cho Tester) */\n");
    Print_C_Array("TESTER_SIGNATURE", chalSignature, 64);

    return 0;
}
