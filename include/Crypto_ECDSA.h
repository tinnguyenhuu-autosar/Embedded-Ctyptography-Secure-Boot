/*******************************************************************************
 * @file    Crypto_ECDSA.h
 * @brief   Crypto Driver - ECDSA P-256 Digital Signature Interface
 * @details API cho thuật toán chữ ký số ECDSA với curve NIST P-256 (secp256r1)
 *
 * @author  HALA Academy
 * @version 1.0.0
 * @date    2026-01-02
 *
 * @note    ECDSA (Elliptic Curve Digital Signature Algorithm):
 *
 *          1. KEY GENERATION:
 *             - Private key d: Số ngẫu nhiên trong [1, n-1] (n = order của
 *curve)
 *             - Public key Q = d × G (G = generator point của curve)
 *
 *          2. SIGN (với private key):
 *             - Input: Hash của message (32 bytes từ SHA-256)
 *             - Output: Signature (R, S) - mỗi cái 32 bytes
 *             - Algorithm:
 *               1) Chọn k ngẫu nhiên trong [1, n-1]
 *               2) Tính (x1, y1) = k × G
 *               3) R = x1 mod n
 *               4) S = k^(-1) × (hash + R × d) mod n
 *
 *          3. VERIFY (với public key):
 *             - Input: Hash + Signature (R, S) + Public key Q
 *             - Output: Valid hoặc Invalid
 *             - Algorithm:
 *               1) Tính w = S^(-1) mod n
 *               2) Tính u1 = hash × w mod n
 *               3) Tính u2 = R × w mod n
 *               4) Tính (x1, y1) = u1 × G + u2 × Q
 *               5) Valid nếu R == x1 mod n
 *
 *          NIST P-256 Parameters:
 *          - p = 2^256 - 2^224 + 2^192 + 2^96 - 1
 *          - n =
 *FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
 *          - Key size: 256 bits (32 bytes)
 ******************************************************************************/

#ifndef CRYPTO_ECDSA_H
#define CRYPTO_ECDSA_H

/*===========================================================================*/
/*                              INCLUDES                                      */
/*===========================================================================*/
#include "Crypto_Types.h"

/*===========================================================================*/
/*                    ECDSA API FUNCTIONS                                     */
/*===========================================================================*/

/**
 * @brief   Tạo cặp khóa Private/Public mới cho ECDSA P-256
 *
 * @param[out] keyPair  Structure sẽ chứa cặp khóa được tạo
 *
 * @return  E_OK     - Tạo key thành công
 * @return  E_NOT_OK - Lỗi (keyPair NULL hoặc RNG failure)
 *
 * @details Output:
 *          - keyPair->privateKey[32]: Private key (scalar d)
 *          - keyPair->publicKeyX[32]: Tọa độ X của public key
 *          - keyPair->publicKeyY[32]: Tọa độ Y của public key
 *          - keyPair->isValid: TRUE nếu key hợp lệ
 *
 * @warning - Private key PHẢI được bảo mật, KHÔNG chia sẻ
 *          - Trong ECU thực, nên dùng HSM để tạo và lưu key
 *
 * @code
 * Crypto_ECDSA_KeyPairType myKeyPair;
 * if (Crypto_ECDSA_GenerateKeyPair(&myKeyPair) == E_OK) {
 *     // Key pair ready
 *     printf("Private key generated (KEEP SECRET!)\n");
 * }
 * @endcode
 */
Std_ReturnType Crypto_ECDSA_GenerateKeyPair(Crypto_ECDSA_KeyPairType *keyPair);

/**
 * @brief   Nạp private key từ bên ngoài vào Crypto Driver
 *
 * @param[in] keyId       ID của key slot trong driver
 * @param[in] privateKey  Private key 32 bytes
 * @param[in] keyLength   Độ dài key (phải = 32)
 *
 * @return  E_OK                     - Set key thành công
 * @return  CRYPTO_E_KEY_SIZE_MISMATCH - keyLength != 32
 * @return  E_NOT_OK                 - Lỗi khác
 *
 * @note    Key được lưu trong driver cho đến khi bị overwrite.
 *          Trong demo này dùng memory; ECU thực dùng HSM.
 *
 * @code
 * Crypto_ECDSA_SetPrivateKey(KEY_SLOT_SIGN, myKeyPair.privateKey, 32);
 * @endcode
 */
Std_ReturnType Crypto_ECDSA_SetPrivateKey(uint32 keyId, const uint8 *privateKey,
                                          uint32 keyLength);

/**
 * @brief   Nạp public key từ bên ngoài vào Crypto Driver
 *
 * @param[in] keyId       ID của key slot
 * @param[in] publicKeyX  Tọa độ X của public key (32 bytes)
 * @param[in] publicKeyY  Tọa độ Y của public key (32 bytes)
 * @param[in] keyLength   Độ dài mỗi tọa độ (phải = 32)
 *
 * @return  E_OK     - Set key thành công
 * @return  E_NOT_OK - Lỗi
 *
 * @note    Public key được dùng để VERIFY chữ ký.
 *          Có thể nhận từ certificate hoặc pre-provisioned.
 *
 * @code
 * Crypto_ECDSA_SetPublicKey(KEY_SLOT_VERIFY,
 *                           senderPubKeyX, senderPubKeyY, 32);
 * @endcode
 */
Std_ReturnType Crypto_ECDSA_SetPublicKey(uint32 keyId, const uint8 *publicKeyX,
                                         const uint8 *publicKeyY,
                                         uint32 keyLength);

/**
 * @brief   Tạo chữ ký số ECDSA cho một digest (hash)
 *
 * @param[in]     keyId           ID của private key đã set
 * @param[in]     digest          Hash của message (32 bytes từ SHA-256)
 * @param[in]     digestLength    Độ dài digest (phải = 32)
 * @param[out]    signature       Buffer nhận chữ ký (tối thiểu 64 bytes)
 * @param[in,out] signatureLength [in] Kích thước buffer
 *                                [out] Độ dài signature thực tế (64)
 *
 * @return  E_OK                    - Ký thành công
 * @return  CRYPTO_E_KEY_NOT_VALID  - Private key chưa được set
 * @return  CRYPTO_E_SMALL_BUFFER   - Buffer < 64 bytes
 * @return  E_NOT_OK                - Lỗi khác
 *
 * @details Signature output format:
 *          - signature[0..31]  = R (32 bytes)
 *          - signature[32..63] = S (32 bytes)
 *
 * @warning - INPUT là DIGEST (hash), KHÔNG phải message gốc!
 *          - Phải hash message trước bằng SHA-256
 *          - Mỗi lần ký tạo signature khác nhau (do random k)
 *
 * @code
 * // Bước 1: Hash message
 * uint8 digest[32];
 * Crypto_SHA256_Calculate(message, msgLen, digest, &digestLen);
 *
 * // Bước 2: Set private key
 * Crypto_ECDSA_SetPrivateKey(KEY_SLOT_SIGN, privateKey, 32);
 *
 * // Bước 3: Sign
 * uint8 signature[64];
 * uint32 sigLen = 64;
 * Crypto_ECDSA_Sign(KEY_SLOT_SIGN, digest, 32, signature, &sigLen);
 * @endcode
 */
Std_ReturnType Crypto_ECDSA_Sign(uint32 keyId, const uint8 *digest,
                                 uint32 digestLength, uint8 *signature,
                                 uint32 *signatureLength);

/**
 * @brief   Xác thực chữ ký số ECDSA
 *
 * @param[in]  keyId           ID của public key đã set
 * @param[in]  digest          Hash của message gốc (32 bytes)
 * @param[in]  digestLength    Độ dài digest
 * @param[in]  signature       Chữ ký cần verify (64 bytes: R + S)
 * @param[in]  signatureLength Độ dài signature
 * @param[out] verifyResult    Kết quả xác thực
 *
 * @return  E_OK     - Verify hoàn thành (kiểm tra verifyResult)
 * @return  E_NOT_OK - Lỗi tham số hoặc key
 *
 * @details verifyResult values:
 *          - CRYPTO_E_VER_OK:     Signature HỢP LỆ ✓
 *          - CRYPTO_E_VER_NOT_OK: Signature KHÔNG HỢP LỆ ✗
 *
 * @note    - Cần public key của người ký
 *          - Digest phải được tính từ cùng message gốc
 *          - Nếu message bị sửa 1 bit → verify FAIL
 *
 * @code
 * Crypto_VerifyResultType result;
 *
 * // Set public key của sender
 * Crypto_ECDSA_SetPublicKey(KEY_SLOT_VERIFY, pubKeyX, pubKeyY, 32);
 *
 * // Verify
 * Crypto_ECDSA_Verify(KEY_SLOT_VERIFY, digest, 32, signature, 64, &result);
 *
 * if (result == CRYPTO_E_VER_OK) {
 *     printf("Signature valid!\n");
 * } else {
 *     printf("Signature INVALID - possible tampering!\n");
 * }
 * @endcode
 */
Std_ReturnType Crypto_ECDSA_Verify(uint32 keyId, const uint8 *digest,
                                   uint32 digestLength, const uint8 *signature,
                                   uint32 signatureLength,
                                   Crypto_VerifyResultType *verifyResult);

/**
 * @brief   Lấy public key từ private key đã set
 *
 * @param[in]  keyId       ID của key slot chứa private key
 * @param[out] publicKeyX  Buffer nhận tọa độ X (32 bytes)
 * @param[out] publicKeyY  Buffer nhận tọa độ Y (32 bytes)
 * @param[in]  keyLength   Độ dài buffer (phải = 32)
 *
 * @return  E_OK                   - Thành công
 * @return  CRYPTO_E_KEY_NOT_VALID - Private key chưa set
 * @return  E_NOT_OK               - Lỗi
 *
 * @details Tính Q = d × G từ private key d.
 *          Hữu ích khi chỉ có private key và cần derive public key.
 */
Std_ReturnType Crypto_ECDSA_GetPublicKey(uint32 keyId, uint8 *publicKeyX,
                                         uint8 *publicKeyY, uint32 keyLength);

#endif /* CRYPTO_ECDSA_H */
