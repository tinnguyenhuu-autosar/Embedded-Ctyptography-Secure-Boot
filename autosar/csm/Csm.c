/*******************************************************************************
 * @file    Csm.c
 * @brief   Crypto Service Manager Implementation
 * @details Triển khai CSM - API layer cho Application
 *
 * @author  HALA Academy
 * @version 1.0.0
 * @date    2026-01-02
 ******************************************************************************/

/*===========================================================================*/
/*                              INCLUDES                                      */
/*===========================================================================*/
#include "Csm.h"
#include "Csm_Cfg.h"
#include "CryIf.h"
#include "Crypto_ECDSA.h"
#include <string.h>

/*===========================================================================*/
/*                    JOB CONFIGURATIONS                                      */
/*===========================================================================*/
/**
 * @brief Số lượng job configs – lấy từ Csm_Cfg.h
 *
 * @note  Bảng cấu hình Csm_JobConfigs[] được định nghĩa trong config/Csm_Cfg.c
 *        Trong AUTOSAR thực, file config được generate từ ARXML.
 */
#define NUM_JOB_CONFIGS CSM_NUM_JOBS

/*===========================================================================*/
/*                    INTERNAL FUNCTIONS                                      */
/*===========================================================================*/
/**
 * @brief   Tìm job config theo jobId
 *
 * @param[in] jobId  ID cần tìm
 *
 * @return  Con trỏ đến job config, hoặc NULL nếu không tìm thấy
 */
static const Crypto_JobConfigType *Csm_GetJobConfig(uint32 jobId) {
  uint32 i;

  for (i = 0u; i < NUM_JOB_CONFIGS; i++) {
    if (Csm_JobConfigs[i].jobId == jobId) {
      return &Csm_JobConfigs[i];
    }
  }

  return NULL_PTR;
}

/*===========================================================================*/
/*              HÀM PUBLIC: CSM_INIT                                          */
/*===========================================================================*/
Std_ReturnType Csm_Init(void) {
  /* Khởi tạo CryIf layer */
  return CryIf_Init();
}

/*===========================================================================*/
/*              HÀM PUBLIC: CSM_HASH                                          */
/*===========================================================================*/
Std_ReturnType Csm_Hash(uint32 jobId, Crypto_OperationModeType mode,
                        const uint8 *dataPtr, uint32 dataLength,
                        uint8 *resultPtr, uint32 *resultLengthPtr) {
  const Crypto_JobConfigType *config;
  Crypto_JobType job;

  /* Tìm job config */
  config = Csm_GetJobConfig(jobId);
  if (config == NULL_PTR) {
    return E_NOT_OK;
  }

  /* Kiểm tra đây là hash job */
  if (config->service != CRYPTO_SERVICE_HASH) {
    return E_NOT_OK;
  }

  /*-----------------------------------------------------------------------
   * Chuẩn bị job structure
   *-----------------------------------------------------------------------*/
  memset(&job, 0, sizeof(job));
  job.jobConfig = config;
  job.jobData.mode = mode;
  job.jobData.inputPtr = dataPtr;
  job.jobData.inputLength = dataLength;
  job.jobData.outputPtr = resultPtr;
  job.jobData.outputLengthPtr = resultLengthPtr;

  /*-----------------------------------------------------------------------
   * Gọi CryIf để xử lý job
   *
   * CSM → CryIf → Crypto_SHA256
   *-----------------------------------------------------------------------*/
  return CryIf_ProcessJob(0u, &job);
}

/*===========================================================================*/
/*              HÀM PUBLIC: CSM_SIGNATUREGENERATE                             */
/*===========================================================================*/
Std_ReturnType Csm_SignatureGenerate(uint32 jobId,
                                     Crypto_OperationModeType mode,
                                     const uint8 *dataPtr, uint32 dataLength,
                                     uint8 *resultPtr,
                                     uint32 *resultLengthPtr) {
  const Crypto_JobConfigType *config;
  Crypto_JobType job;

  /* Tìm job config */
  config = Csm_GetJobConfig(jobId);
  if (config == NULL_PTR) {
    return E_NOT_OK;
  }

  /* Kiểm tra đây là signature generate job */
  if (config->service != CRYPTO_SERVICE_SIGNATURE_GEN) {
    return E_NOT_OK;
  }

  /*-----------------------------------------------------------------------
   * Chuẩn bị job structure
   *-----------------------------------------------------------------------*/
  memset(&job, 0, sizeof(job));
  job.jobConfig = config;
  job.jobData.mode = mode;
  job.jobData.inputPtr = dataPtr;
  job.jobData.inputLength = dataLength;
  job.jobData.outputPtr = resultPtr;
  job.jobData.outputLengthPtr = resultLengthPtr;

  /*-----------------------------------------------------------------------
   * Gọi CryIf để xử lý job
   *
   * CSM → CryIf → Crypto_SHA256 (hash) → Crypto_ECDSA (sign)
   *-----------------------------------------------------------------------*/
  return CryIf_ProcessJob(0u, &job);
}

/*===========================================================================*/
/*              HÀM PUBLIC: CSM_SIGNATUREVERIFY                               */
/*===========================================================================*/
Std_ReturnType Csm_SignatureVerify(uint32 jobId, Crypto_OperationModeType mode,
                                   const uint8 *dataPtr, uint32 dataLength,
                                   const uint8 *signaturePtr,
                                   uint32 signatureLength,
                                   Crypto_VerifyResultType *verifyPtr) {
  const Crypto_JobConfigType *config;
  Crypto_JobType job;

  /* Tìm job config */
  config = Csm_GetJobConfig(jobId);
  if (config == NULL_PTR) {
    return E_NOT_OK;
  }

  /* Kiểm tra đây là signature verify job */
  if (config->service != CRYPTO_SERVICE_SIGNATURE_VER) {
    return E_NOT_OK;
  }

  /*-----------------------------------------------------------------------
   * Chuẩn bị job structure
   *-----------------------------------------------------------------------*/
  memset(&job, 0, sizeof(job));
  job.jobConfig = config;
  job.jobData.mode = mode;
  job.jobData.inputPtr = dataPtr;
  job.jobData.inputLength = dataLength;
  job.jobData.secondaryInputPtr = signaturePtr;
  job.jobData.secondaryInputLength = signatureLength;
  job.jobData.verifyPtr = verifyPtr;

  /*-----------------------------------------------------------------------
   * Gọi CryIf để xử lý job
   *
   * CSM → CryIf → Crypto_SHA256 (hash) → Crypto_ECDSA (verify)
   *-----------------------------------------------------------------------*/
  return CryIf_ProcessJob(0u, &job);
}

/*===========================================================================*/
/*              HÀM PUBLIC: CSM_KEYELEMENTSET_PRIVATEKEY                      */
/*===========================================================================*/
Std_ReturnType Csm_KeyElementSet_PrivateKey(uint32 keyId,
                                            const uint8 *privateKey,
                                            uint32 keyLength) {
  /*-----------------------------------------------------------------------
   * Simplified key management: trực tiếp gọi Crypto Driver
   *
   * Trong AUTOSAR đầy đủ:
   * - CSM → KeyM → CryIf → Crypto Driver
   * - Có thêm access control, key lifetime management, etc.
   *-----------------------------------------------------------------------*/
  return Crypto_ECDSA_SetPrivateKey(keyId, privateKey, keyLength);
}

/*===========================================================================*/
/*              HÀM PUBLIC: CSM_KEYELEMENTSET_PUBLICKEY                       */
/*===========================================================================*/
Std_ReturnType Csm_KeyElementSet_PublicKey(uint32 keyId,
                                           const uint8 *publicKeyX,
                                           const uint8 *publicKeyY,
                                           uint32 keyLength) {
  return Crypto_ECDSA_SetPublicKey(keyId, publicKeyX, publicKeyY, keyLength);
}
