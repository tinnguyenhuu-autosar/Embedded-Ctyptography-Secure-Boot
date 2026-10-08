/*******************************************************************************
 * @file    CryIf.h
 * @brief   Crypto Interface Layer
 * @details CryIf layer nằm giữa CSM và Crypto Driver, routing jobs đến driver
 *
 * @author  HALA Academy
 * @version 1.0.0
 * @date    2026-01-02
 *
 * @note    TRONG AUTOSAR CLASSIC:
 *
 *          ┌──────────────────────────────────────────────────────────────┐
 *          │                    Application                                │
 *          │                        ↓                                      │
 *          │              Crypto Service Manager (CSM)                     │
 *          │    - Quản lý jobs, queues, priorities                        │
 *          │    - Cung cấp API cho application                            │
 *          │                        ↓                                      │
 *          │              Crypto Interface (CryIf)  ← CHÚNG TA Ở ĐÂY       │
 *          │    - Route jobs đến đúng Crypto Driver                       │
 *          │    - Abstract hóa nhiều drivers                              │
 *          │                        ↓                                      │
 *          │              Crypto Driver (Crypto)                          │
 *          │    - Thực hiện thuật toán crypto                             │
 *          │    - Có thể là SW hoặc HW accelerator/HSM                    │
 *          └──────────────────────────────────────────────────────────────┘
 *
 *          Trong demo này, CryIf đơn giản route trực tiếp đến
 *          Crypto_SHA256 hoặc Crypto_ECDSA dựa trên job config.
 ******************************************************************************/

#ifndef CRYIF_H
#define CRYIF_H

/*===========================================================================*/
/*                              INCLUDES                                      */
/*===========================================================================*/
#include "Crypto_Types.h"

/*===========================================================================*/
/*                    CRYIF API FUNCTIONS                                     */
/*===========================================================================*/

/**
 * @brief   Xử lý một Crypto Job
 *
 * @param[in]     channelId  ID của channel (không dùng trong demo đơn giản)
 * @param[in,out] job        Con trỏ đến job cần xử lý
 *
 * @return  E_OK     - Job xử lý thành công
 * @return  E_NOT_OK - Lỗi xử lý
 *
 * @details CryIf nhận job từ CSM và route đến đúng Crypto Driver:
 *          - CRYPTO_SERVICE_HASH → Crypto_SHA256
 *          - CRYPTO_SERVICE_SIGNATURE_GEN → Crypto_ECDSA_Sign
 *          - CRYPTO_SERVICE_SIGNATURE_VER → Crypto_ECDSA_Verify
 *
 * @note    Trong hệ thống thực, CryIf có thể:
 *          - Route đến nhiều drivers khác nhau (SW, HW, HSM)
 *          - Load balancing giữa các crypto engines
 *          - Handle driver busy/queueing
 */
Std_ReturnType CryIf_ProcessJob(uint32 channelId, Crypto_JobType *job);

/**
 * @brief   Khởi tạo CryIf module
 *
 * @return  E_OK     - Khởi tạo thành công
 * @return  E_NOT_OK - Lỗi
 *
 * @note    Gọi khi startup, trước khi sử dụng các API khác
 */
Std_ReturnType CryIf_Init(void);

#endif /* CRYIF_H */
