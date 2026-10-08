/*******************************************************************************
 * @file    example_08_verify_ecu.c
 * @brief   Firmware chạy trên ECU (STM32F103) chỉ làm nhiệm vụ Verify
 *
 * @details Mô phỏng Bootloader của ECU trên xe:
 *          1. KHÔNG có mã lệnh tạo Key (KeyGen)
 *          2. KHÔNG có Private Key (không thể ký - Sign)
 *          3. Nạp thẳng Public Key cứng (từ nhà máy)
 *          4. Verify Firmware + Signature được đọc từ Flash
 *
 *          *Lưu ý: Firmware này chạy Bare-metal trên STM32F103.*
 *
 * @author  HALA Academy
 * @version 1.0.0
 ******************************************************************************/

#include "Csm.h"
#include "uart_log.h"
#include <string.h>

/*===========================================================================*/
/*  DỮ LIỆU CỐ ĐỊNH (Hardcoded) — Lấy từ Output của Tool OEM (example_07)    */
/*===========================================================================*/

/* 1. Firmware Content (Mô phỏng đọc từ Flash) */
const char* const FIRMWARE_FLASH = "HALA ECU FW v3.0 - Official 2026";

/* 2. Public Key (Ghi vào OTP/ROM của ECU) */
const uint8 PUBLIC_KEY_OEM[64] = {
    0x3E, 0x94, 0x49, 0x40, 0x73, 0xCC, 0xFD, 0xD4, 
    0x18, 0x8D, 0x14, 0x12, 0x0E, 0xA1, 0x18, 0x2E, 
    0x7D, 0x28, 0xAB, 0xE4, 0x1B, 0x52, 0xC4, 0xD3, 
    0x9E, 0xD8, 0xA7, 0xFE, 0x20, 0x06, 0xDF, 0x84, 
    0x8A, 0x97, 0x91, 0x1E, 0xEB, 0xCD, 0x9F, 0xA4, 
    0x05, 0xE9, 0x4A, 0x8D, 0xEA, 0xB0, 0x7E, 0xE7, 
    0x88, 0x1B, 0xCC, 0x4E, 0xE7, 0xFB, 0xD2, 0x45, 
    0x0B, 0x8A, 0x59, 0x04, 0x39, 0x03, 0x3D, 0x1F
};

/* 3. Signature (Được nạp chung với Firmware vào Flash) */
const uint8 FIRMWARE_SIGNATURE[64] = {
    0x02, 0x71, 0x1C, 0xC1, 0xFB, 0x3C, 0xF8, 0x3D, 
    0xC7, 0x66, 0xFD, 0xB0, 0x5F, 0xB8, 0x40, 0xC1, 
    0xC8, 0x4A, 0x1C, 0x6B, 0x70, 0xCB, 0xE2, 0xCD, 
    0x55, 0xCD, 0x2D, 0xAF, 0xCB, 0x6E, 0x0B, 0x35, 
    0xE0, 0x12, 0xFB, 0xDD, 0xA7, 0x62, 0xAB, 0x96, 
    0xA2, 0x85, 0x16, 0x31, 0xDB, 0xE1, 0xD3, 0xB0, 
    0xE5, 0xA6, 0x62, 0xAF, 0x07, 0x09, 0x2B, 0x25, 
    0xB6, 0xD6, 0xCE, 0x98, 0xB9, 0x06, 0x58, 0x96
};

/*===========================================================================*/
/*                              MAIN BOOTLOADER                               */
/*===========================================================================*/
int main(void) {
    /*--- BSP Init ---*/
    Log_Init();
    Led_Init();

    Log_Print("\r\n\r\n");
    Log_Print("========================================================\r\n");
    Log_Print("  [ECU BOOTLOADER] AUTOSAR Secure Boot Verify Only      \r\n");
    Log_Print("  Target: STM32F103 Cortex-M3                           \r\n");
    Log_Print("========================================================\r\n\r\n");

    /* 1. Khởi tạo Crypto Stack */
    Log_Print("-> 1. Csm_Init()...\r\n");
    if (Csm_Init() != E_OK) {
        Log_Print("   [LỖI] Không thể khởi tạo Crypto Stack.\r\n");
        while(1) { Led_Toggle(); Delay_ms(100); }
    }
    Log_Print("   [OK] Crypto Stack sẵn sàng.\r\n\r\n");

    /* 2. Nạp Public Key vào Slot (Mô phỏng nạp từ OTP) */
    Log_Print("-> 2. Đọc Public Key từ ROM/OTP...\r\n");
    Std_ReturnType ret = Csm_KeyElementSet_PublicKey(
        KEY_SLOT_VERIFY, 
        PUBLIC_KEY_OEM,         /* PublicKey X */
        PUBLIC_KEY_OEM + 32,    /* PublicKey Y */
        32                      /* Kích thước mỗi trục */
    );
    if (ret != E_OK) {
        Log_Print("   [LỖI] Nạp Public Key thất bại.\r\n");
        while(1) { Led_Toggle(); Delay_ms(100); }
    }
    Log_Print("   [OK] Đã cấu hình Public Key vào Slot.\r\n\r\n");

    /* 3. Verify Firmware bằng CSM */
    Log_Print("-> 3. Gọi Csm_SignatureVerify()...\r\n");
    Log_Print("   Firmware: \"");
    Log_Print(FIRMWARE_FLASH);
    Log_Print("\"\r\n");

    Crypto_VerifyResultType verResult;
    ret = Csm_SignatureVerify(
        JOB_ID_VERIFY, 
        CRYPTO_OPERATIONMODE_SINGLECALL,
        (const uint8 *)FIRMWARE_FLASH, 
        (uint32)strlen(FIRMWARE_FLASH),
        FIRMWARE_SIGNATURE, 
        sizeof(FIRMWARE_SIGNATURE), 
        &verResult
    );

    /* 4. Đánh giá kết quả */
    Log_Print("\r\n========================================================\r\n");
    if (ret == E_OK && verResult == CRYPTO_E_VER_OK) {
        Log_Print("  [KẾT QUẢ] SIGNATURE HỢP LỆ! Firmware là chính hãng.\r\n");
        Log_Print("  [ACTION]  JUMP TO APPLICATION...\r\n");
        Led_On();
    } else {
        Log_Print("  [KẾT QUẢ] ⛔️ SIGNATURE BỊ SAI! Firmware đã bị sửa đổi.\r\n");
        Log_Print("  [ACTION]  HỆ THỐNG TỪ CHỐI BOOT!\r\n");
        Led_Off();
    }
    Log_Print("========================================================\r\n");

    /* Nháy đèn báo hiệu hệ thống vẫn sống */
    while (1) {
        Led_Toggle();
        Delay_ms(1000);
    }

    return 0;
}
