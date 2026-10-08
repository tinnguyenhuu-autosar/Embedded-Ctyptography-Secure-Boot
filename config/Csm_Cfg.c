/*******************************************************************************
 * @file    Csm_Cfg.c
 * @brief   CSM – Định nghĩa bảng cấu hình Job
 * @details Trong AUTOSAR thực, file này được generate từ ARXML.
 *          Demo hardcode để học viên thấy cấu trúc bên trong dễ hơn.
 *
 * @author  HALA Academy
 * @version 1.0.0
 * @date    2026-01-02
 ******************************************************************************/

/*===========================================================================*/
/*                              INCLUDES                                      */
/*===========================================================================*/
#include "Csm_Cfg.h"
#include "Csm.h"

/*===========================================================================*/
/*                    JOB CONFIGURATIONS                                      */
/*===========================================================================*/
/**
 * @brief Cấu hình các jobs được định nghĩa sẵn
 *
 * @note  Trong AUTOSAR thực, các job configs được generate từ ARXML.
 *        Ở đây ta hardcode cho demo.
 *
 * | Job ID              | Service          | Algorithm       | Key Slot     |
 * |---------------------|------------------|-----------------|--------------|
 * | JOB_ID_HASH_SHA256  | HASH             | SHA-256         | 0 (no key)   |
 * | JOB_ID_SIGN         | SIGNATURE_GEN    | ECDSA P-256     | KEY_SLOT_SIGN|
 * | JOB_ID_VERIFY       | SIGNATURE_VER    | ECDSA P-256     | KEY_SLOT_VERIFY|
 */
const Crypto_JobConfigType Csm_JobConfigs[CSM_NUM_JOBS] = {
    /* JOB_ID_HASH_SHA256 (1) */
    {
        .jobId = JOB_ID_HASH_SHA256,
        .service = CRYPTO_SERVICE_HASH,
        .algorithm = CRYPTO_ALGOFAM_SHA2_256,
        .keyId = 0u /* Hash không cần key */
    },

    /* JOB_ID_SIGN (2) */
    {
        .jobId = JOB_ID_SIGN,
        .service = CRYPTO_SERVICE_SIGNATURE_GEN,
        .algorithm = CRYPTO_ALGOFAM_ECCNIST_P256,
        .keyId = KEY_SLOT_SIGN
    },

    /* JOB_ID_VERIFY (3) */
    {
        .jobId = JOB_ID_VERIFY,
        .service = CRYPTO_SERVICE_SIGNATURE_VER,
        .algorithm = CRYPTO_ALGOFAM_ECCNIST_P256,
        .keyId = KEY_SLOT_VERIFY
    }
};
