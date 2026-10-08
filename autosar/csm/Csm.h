/*******************************************************************************
 * @file    Csm.h
 * @brief   Crypto Service Manager (CSM) - Application Interface
 * @details CSM cung cấp API crypto cho Application layer
 *          Đây là layer cao nhất trong Crypto Stack
 *
 * @author  HALA Academy
 * @version 1.0.0
 * @date    2026-01-02
 *
 * @note    TRONG AUTOSAR CLASSIC:
 *
 *          CSM là "cửa ngõ" duy nhất để Application truy cập crypto services.
 *
 *          Ưu điểm của kiến trúc này:
 *          1. Abstraction: App không cần biết chi tiết thuật toán
 *          2. Portability: Dễ dàng đổi backend (SW ↔ HSM)
 *          3. Security: Kiểm soát truy cập crypto theo job/key
 *          4. Resource Management: Queue jobs, handle priorities
 *
 *          ┌────────────────────────────────────────────────────────┐
 *          │              APPLICATION                                │
 *          │                  ↓                                      │
 *          │    Csm_Hash() / Csm_SignatureGenerate() / ...          │ ← API
 *          ├────────────────────────────────────────────────────────┤
 *          │                CSM Internal                             │
 *          │    - Job Management                                     │
 *          │    - Queue per priority                                 │
 *          │    - Callback handling                                  │
 *          ├────────────────────────────────────────────────────────┤
 *          │              CryIf_ProcessJob()                         │
 *          └────────────────────────────────────────────────────────┘
 ******************************************************************************/

#ifndef CSM_H
#define CSM_H

/*===========================================================================*/
/*                              INCLUDES                                      */
/*===========================================================================*/
#include "Crypto_Types.h"

/*===========================================================================*/
/*                    CSM API FUNCTIONS                                       */
/*===========================================================================*/

/**
 * @brief   Khởi tạo CSM module
 *
 * @return  E_OK     - Khởi tạo thành công
 * @return  E_NOT_OK - Lỗi
 *
 * @details Gọi khi startup, trước khi sử dụng các API khác.
 *          Khởi tạo job configurations và internal state.
 */
Std_ReturnType Csm_Init(void);

/*===========================================================================*/
/*                    HASH SERVICE                                            */
/*===========================================================================*/

/**
 * @brief   Tính hash của dữ liệu
 *
 * @param[in]     jobId           ID của hash job (đã config với algorithm)
 * @param[in]     mode            Chế độ: SINGLECALL, START, UPDATE, FINISH
 * @param[in]     dataPtr         Con trỏ đến dữ liệu cần hash
 * @param[in]     dataLength      Độ dài dữ liệu (bytes)
 * @param[out]    resultPtr       Buffer nhận digest (khi FINISH/SINGLECALL)
 * @param[in,out] resultLengthPtr Kích thước buffer / độ dài output
 *
 * @return  E_OK     - Thành công
 * @return  E_NOT_OK - Lỗi
 *
 * @details
 * **Cách sử dụng:**
 *
 * 1) **SINGLECALL** - Hash toàn bộ trong 1 lần:
 * @code
 * uint8 digest[32];
 * uint32 digestLen = 32;
 * Csm_Hash(JOB_ID_HASH_SHA256, CRYPTO_OPERATIONMODE_SINGLECALL,
 *          data, dataLen, digest, &digestLen);
 * @endcode
 *
 * 2) **Streaming** - Hash dữ liệu lớn theo chunks:
 * @code
 * // Bắt đầu
 * Csm_Hash(jobId, CRYPTO_OPERATIONMODE_START, NULL, 0, NULL, NULL);
 *
 * // Thêm từng chunk
 * Csm_Hash(jobId, CRYPTO_OPERATIONMODE_UPDATE, chunk1, len1, NULL, NULL);
 * Csm_Hash(jobId, CRYPTO_OPERATIONMODE_UPDATE, chunk2, len2, NULL, NULL);
 *
 * // Kết thúc và lấy digest
 * Csm_Hash(jobId, CRYPTO_OPERATIONMODE_FINISH, NULL, 0, digest, &digestLen);
 * @endcode
 */
Std_ReturnType Csm_Hash(uint32 jobId, Crypto_OperationModeType mode,
                        const uint8 *dataPtr, uint32 dataLength,
                        uint8 *resultPtr, uint32 *resultLengthPtr);

/*===========================================================================*/
/*                    SIGNATURE SERVICE                                       */
/*===========================================================================*/

/**
 * @brief   Tạo chữ ký số cho dữ liệu
 *
 * @param[in]     jobId           ID của sign job (đã config với keyId)
 * @param[in]     mode            Chế độ (thường dùng SINGLECALL)
 * @param[in]     dataPtr         Dữ liệu cần ký (message gốc)
 * @param[in]     dataLength      Độ dài dữ liệu
 * @param[out]    resultPtr       Buffer nhận signature (64 bytes cho P-256)
 * @param[in,out] resultLengthPtr Kích thước buffer / độ dài output
 *
 * @return  E_OK     - Ký thành công
 * @return  E_NOT_OK - Lỗi
 *
 * @details CSM tự động thực hiện:
 *          1. Hash message bằng SHA-256
 *          2. Sign hash bằng ECDSA với private key từ job config
 *
 * @note    Job phải được cấu hình với keyId chứa private key trước khi gọi.
 *
 * @code
 * // Đã set private key: Crypto_ECDSA_SetPrivateKey(KEY_SLOT_SIGN, ...)
 *
 * uint8 signature[64];
 * uint32 sigLen = 64;
 *
 * Csm_SignatureGenerate(JOB_ID_SIGN, CRYPTO_OPERATIONMODE_SINGLECALL,
 *                       message, msgLen, signature, &sigLen);
 * @endcode
 */
Std_ReturnType Csm_SignatureGenerate(uint32 jobId,
                                     Crypto_OperationModeType mode,
                                     const uint8 *dataPtr, uint32 dataLength,
                                     uint8 *resultPtr, uint32 *resultLengthPtr);

/**
 * @brief   Xác thực chữ ký số
 *
 * @param[in]  jobId           ID của verify job (đã config với keyId)
 * @param[in]  mode            Chế độ (thường dùng SINGLECALL)
 * @param[in]  dataPtr         Dữ liệu gốc (message)
 * @param[in]  dataLength      Độ dài dữ liệu
 * @param[in]  signaturePtr    Chữ ký cần verify
 * @param[in]  signatureLength Độ dài chữ ký
 * @param[out] verifyPtr       Kết quả verify
 *
 * @return  E_OK     - Verify hoàn thành (xem verifyPtr cho kết quả)
 * @return  E_NOT_OK - Lỗi
 *
 * @details CSM tự động thực hiện:
 *          1. Hash lại message bằng SHA-256
 *          2. Verify signature bằng ECDSA với public key
 *
 *          verifyPtr values:
 *          - CRYPTO_E_VER_OK: Signature hợp lệ → message chưa bị sửa đổi
 *          - CRYPTO_E_VER_NOT_OK: Signature không hợp lệ → message bị
 * tampering!
 *
 * @warning Nếu verify trả về CRYPTO_E_VER_NOT_OK, KHÔNG được tin tưởng message!
 *
 * @code
 * // Đã set public key: Crypto_ECDSA_SetPublicKey(KEY_SLOT_VERIFY, ...)
 *
 * Crypto_VerifyResultType result;
 *
 * Csm_SignatureVerify(JOB_ID_VERIFY, CRYPTO_OPERATIONMODE_SINGLECALL,
 *                     message, msgLen, signature, 64, &result);
 *
 * if (result == CRYPTO_E_VER_OK) {
 *     // Message is authentic
 * } else {
 *     // Message may be tampered!
 * }
 * @endcode
 */
Std_ReturnType Csm_SignatureVerify(uint32 jobId, Crypto_OperationModeType mode,
                                   const uint8 *dataPtr, uint32 dataLength,
                                   const uint8 *signaturePtr,
                                   uint32 signatureLength,
                                   Crypto_VerifyResultType *verifyPtr);

/*===========================================================================*/
/*                    KEY MANAGEMENT (Simplified)                             */
/*===========================================================================*/

/**
 * @brief   Set ECDSA private key cho job
 *
 * @param[in] keyId       ID của key slot
 * @param[in] privateKey  Private key data (32 bytes)
 * @param[in] keyLength   Độ dài key
 *
 * @return  E_OK     - Thành công
 * @return  E_NOT_OK - Lỗi
 *
 * @note    Đây là simplified API. Trong AUTOSAR đầy đủ, key management
 *          phức tạp hơn với KeyM module và key elements.
 */
Std_ReturnType Csm_KeyElementSet_PrivateKey(uint32 keyId,
                                            const uint8 *privateKey,
                                            uint32 keyLength);

/**
 * @brief   Set ECDSA public key cho job
 *
 * @param[in] keyId       ID của key slot
 * @param[in] publicKeyX  Public key X coordinate (32 bytes)
 * @param[in] publicKeyY  Public key Y coordinate (32 bytes)
 * @param[in] keyLength   Độ dài mỗi coordinate
 *
 * @return  E_OK     - Thành công
 * @return  E_NOT_OK - Lỗi
 */
Std_ReturnType Csm_KeyElementSet_PublicKey(uint32 keyId,
                                           const uint8 *publicKeyX,
                                           const uint8 *publicKeyY,
                                           uint32 keyLength);

#endif /* CSM_H */
