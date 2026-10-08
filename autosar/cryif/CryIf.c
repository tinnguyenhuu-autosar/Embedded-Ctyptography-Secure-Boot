/*******************************************************************************
 * @file    CryIf.c
 * @brief   Crypto Interface Layer Implementation
 * @details Route jobs từ CSM đến đúng Crypto Driver
 *
 * @author  HALA Academy
 * @version 1.0.0
 * @date    2026-01-02
 ******************************************************************************/

/*===========================================================================*/
/*                              INCLUDES                                      */
/*===========================================================================*/
#include "CryIf.h"
#include "Crypto_ECDSA.h"
#include "Crypto_SHA256.h"
#include <string.h>

/*===========================================================================*/
/*                    INTERNAL STATE                                          */
/*===========================================================================*/
/**
 * @brief Context SHA-256 cho streaming mode
 * @note  Trong hệ thống thực, mỗi job có context riêng
 */
static Crypto_SHA256_ContextType hashContext;

/**
 * @brief Flag đánh dấu hash context đang active
 */
static bool hashContextActive = false;

/*===========================================================================*/
/*              HÀM NỘI BỘ: XỬ LÝ HASH JOB                                    */
/*===========================================================================*/
/**
 * @brief   Xử lý Hash job (SHA-256)
 *
 * @param[in,out] job  Job chứa thông tin hash
 *
 * @return  Kết quả xử lý
 */
static Std_ReturnType CryIf_ProcessHashJob(Crypto_JobType *job) {
  Std_ReturnType result = E_OK;
  Crypto_OperationModeType mode = job->jobData.mode;

  /*-----------------------------------------------------------------------
   * XỬ LÝ THEO MODE
   *
   * - START: Khởi tạo context mới
   * - UPDATE: Thêm data vào context
   * - FINISH: Padding và xuất digest
   * - SINGLECALL: Kết hợp cả 3 trong 1 lần gọi
   *-----------------------------------------------------------------------*/

  /* START mode - khởi tạo context */
  if ((mode & CRYPTO_OPERATIONMODE_START) != 0u) {
    result = Crypto_SHA256_Init(&hashContext);
    if (result != E_OK) {
      hashContextActive = false;
      return result;
    }
    hashContextActive = true;
  }

  /* UPDATE mode - thêm data */
  if ((mode & CRYPTO_OPERATIONMODE_UPDATE) != 0u) {
    if (!hashContextActive) {
      return E_NOT_OK; /* Chưa START */
    }

    if ((job->jobData.inputPtr != NULL_PTR) &&
        (job->jobData.inputLength > 0u)) {
      result = Crypto_SHA256_Update(&hashContext, job->jobData.inputPtr,
                                    job->jobData.inputLength);
      if (result != E_OK) {
        return result;
      }
    }
  }

  /* FINISH mode - xuất digest */
  if ((mode & CRYPTO_OPERATIONMODE_FINISH) != 0u) {
    if (!hashContextActive) {
      return E_NOT_OK; /* Chưa START */
    }

    result = Crypto_SHA256_Finish(&hashContext, job->jobData.outputPtr,
                                  job->jobData.outputLengthPtr);

    hashContextActive = false; /* Context không còn valid */
  }

  return result;
}

/*===========================================================================*/
/*              HÀM NỘI BỘ: XỬ LÝ SIGNATURE GENERATE JOB                      */
/*===========================================================================*/
/**
 * @brief   Xử lý Signature Generate job (ECDSA Sign)
 *
 * @param[in,out] job  Job chứa thông tin sign
 *
 * @return  Kết quả xử lý
 *
 * @details Flow:
 *          1. Hash input data bằng SHA-256
 *          2. Sign hash bằng ECDSA với private key
 */
static Std_ReturnType CryIf_ProcessSignatureGenerateJob(Crypto_JobType *job) {
  uint8 digest[CRYPTO_SHA256_DIGEST_SIZE];
  uint32 digestLen = sizeof(digest);
  Std_ReturnType result;

  /* Chỉ hỗ trợ SINGLECALL cho demo */
  if (job->jobData.mode != CRYPTO_OPERATIONMODE_SINGLECALL) {
    /* TODO: Implement streaming mode cho signing */
    return E_NOT_OK;
  }

  /*-----------------------------------------------------------------------
   * BƯỚC 1: Hash message bằng SHA-256
   *
   * ECDSA ký trên DIGEST, không phải message gốc.
   * Điều này cho phép ký message có độ dài bất kỳ.
   *-----------------------------------------------------------------------*/
  result = Crypto_SHA256_Calculate(
      job->jobData.inputPtr, job->jobData.inputLength, digest, &digestLen);

  if (result != E_OK) {
    return result;
  }

  /*-----------------------------------------------------------------------
   * BƯỚC 2: Sign digest bằng ECDSA
   *
   * Sử dụng private key từ key slot được config trong job.
   *-----------------------------------------------------------------------*/
  result =
      Crypto_ECDSA_Sign(job->jobConfig->keyId, digest, digestLen,
                        job->jobData.outputPtr, job->jobData.outputLengthPtr);

  return result;
}

/*===========================================================================*/
/*              HÀM NỘI BỘ: XỬ LÝ SIGNATURE VERIFY JOB                        */
/*===========================================================================*/
/**
 * @brief   Xử lý Signature Verify job (ECDSA Verify)
 *
 * @param[in,out] job  Job chứa thông tin verify
 *
 * @return  Kết quả xử lý
 *
 * @details Flow:
 *          1. Hash input data bằng SHA-256 (giống như khi sign)
 *          2. Verify signature bằng ECDSA với public key
 */
static Std_ReturnType CryIf_ProcessSignatureVerifyJob(Crypto_JobType *job) {
  uint8 digest[CRYPTO_SHA256_DIGEST_SIZE];
  uint32 digestLen = sizeof(digest);
  Std_ReturnType result;

  /* Chỉ hỗ trợ SINGLECALL cho demo */
  if (job->jobData.mode != CRYPTO_OPERATIONMODE_SINGLECALL) {
    return E_NOT_OK;
  }

  /*-----------------------------------------------------------------------
   * BƯỚC 1: Hash message bằng SHA-256
   *
   * Phải hash lại message để so sánh với signature.
   * Nếu message bị sửa đổi, hash sẽ khác → verify fail.
   *-----------------------------------------------------------------------*/
  result = Crypto_SHA256_Calculate(
      job->jobData.inputPtr, job->jobData.inputLength, digest, &digestLen);

  if (result != E_OK) {
    return result;
  }

  /*-----------------------------------------------------------------------
   * BƯỚC 2: Verify signature bằng ECDSA
   *
   * So sánh signature với digest sử dụng public key.
   * Nếu khớp → message chưa bị sửa đổi và được ký bởi người có private key.
   *-----------------------------------------------------------------------*/
  result = Crypto_ECDSA_Verify(
      job->jobConfig->keyId, digest, digestLen, job->jobData.secondaryInputPtr,
      job->jobData.secondaryInputLength, job->jobData.verifyPtr);

  return result;
}

/*===========================================================================*/
/*              HÀM PUBLIC: CRYIF_INIT                                        */
/*===========================================================================*/
Std_ReturnType CryIf_Init(void) {
  /* Reset internal state */
  hashContextActive = false;
  memset(&hashContext, 0, sizeof(hashContext));

  return E_OK;
}

/*===========================================================================*/
/*              HÀM PUBLIC: CRYIF_PROCESSJOB                                  */
/*===========================================================================*/
Std_ReturnType CryIf_ProcessJob(uint32 channelId, Crypto_JobType *job) {
  Std_ReturnType result = E_NOT_OK;

  /* Suppress unused parameter warning */
  (void)channelId;

  /* Kiểm tra tham số */
  if ((job == NULL_PTR) || (job->jobConfig == NULL_PTR)) {
    return E_NOT_OK;
  }

  /*-----------------------------------------------------------------------
   * ROUTE JOB ĐẾN ĐÚNG CRYPTO DRIVER
   *
   * Dựa trên service type trong job config, gọi đúng driver function.
   *-----------------------------------------------------------------------*/
  switch (job->jobConfig->service) {
  case CRYPTO_SERVICE_HASH:
    result = CryIf_ProcessHashJob(job);
    break;

  case CRYPTO_SERVICE_SIGNATURE_GEN:
    result = CryIf_ProcessSignatureGenerateJob(job);
    break;

  case CRYPTO_SERVICE_SIGNATURE_VER:
    result = CryIf_ProcessSignatureVerifyJob(job);
    break;

  default:
    result = E_NOT_OK;
    break;
  }

  return result;
}
