/*******************************************************************************
 * @file    Csm_Cfg.h
 * @brief   CSM – Cấu hình Job / Key / Algorithm
 * @details Trong AUTOSAR thực, file này được generate từ ARXML bằng tool
 *          cấu hình. Ở đây ta hardcode cho demo.
 *
 * @author  HALA Academy
 * @version 1.0.0
 * @date    2026-01-02
 ******************************************************************************/
#ifndef CSM_CFG_H
#define CSM_CFG_H

#ifdef __cplusplus
extern "C" {
#endif

#include "Crypto_Types.h"

/*===========================================================================*/
/*                    SỐ LƯỢNG JOB CONFIGS                                    */
/*===========================================================================*/
#define CSM_NUM_JOBS (3u)

/*===========================================================================*/
/*                    BẢNG CẤU HÌNH JOB (extern)                              */
/*===========================================================================*/
/**
 * @brief  Bảng cấu hình job – khai báo extern, định nghĩa trong Csm_Cfg.c
 *
 * Mỗi phần tử chứa:
 *   - jobId:     ID logic mà Application truyền vào CSM API
 *   - service:   Loại dịch vụ crypto (Hash, Sign, Verify, …)
 *   - algorithm: Thuật toán cụ thể (SHA-256, ECDSA P-256, …)
 *   - keyId:     Key slot/reference nếu service cần key
 */
extern const Crypto_JobConfigType Csm_JobConfigs[CSM_NUM_JOBS];

#ifdef __cplusplus
}
#endif

#endif /* CSM_CFG_H */
