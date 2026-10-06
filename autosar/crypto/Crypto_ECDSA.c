/*******************************************************************************
 * @file    Crypto_ECDSA.c
 * @brief   Crypto Driver - ECDSA P-256 Implementation
 * @details Triển khai ECDSA với curve NIST P-256 sử dụng thư viện micro-ecc
 *
 * @note    Sử dụng thư viện micro-ecc (https://github.com/kmackay/micro-ecc)
 *          - Nhẹ, phù hợp cho embedded systems
 *          - Hỗ trợ nhiều curves: secp160r1, secp192r1, secp224r1, secp256r1,
 *secp256k1
 *          - Không cần malloc, chỉ dùng stack
 *
 * @note    CURVE NIST P-256 (secp256r1):
 *          - Được NIST và NSA khuyến nghị
 *          - An toàn tương đương RSA 3072-bit
 *          - Dùng rộng rãi trong TLS, Bitcoin (P2SH), AUTOSAR...
 ******************************************************************************/

/*===========================================================================*/
/*                              INCLUDES                                      */
/*===========================================================================*/
#include "Crypto_ECDSA.h"
#include "uECC.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*===========================================================================*/
/*                    KEY STORAGE (Demo - trong thực tế dùng HSM)             */
/*===========================================================================*/
/**
 * @brief Structure lưu trữ key trong một slot
 *
 * @warning Trong demo này, keys được lưu trong RAM thông thường.
 *          Trong ECU thực, PHẢI lưu private key trong HSM để bảo mật!
 */
typedef struct
{
  uint8 privateKey[CRYPTO_ECDSA_P256_KEY_SIZE]; /**< Private key d */
  uint8 publicKeyX[CRYPTO_ECDSA_P256_KEY_SIZE]; /**< Public key X  */
  uint8 publicKeyY[CRYPTO_ECDSA_P256_KEY_SIZE]; /**< Public key Y  */
  bool hasPrivateKey;                           /**< Private key được set? */
  bool hasPublicKey;                            /**< Public key được set?  */
} Crypto_ECDSA_KeySlotType;

/**
 * @brief Mảng lưu trữ các key slots
 */
static Crypto_ECDSA_KeySlotType keySlots[CRYPTO_MAX_KEY_SLOTS];

/**
 * @brief Flag đánh dấu RNG đã được khởi tạo
 */
static bool rngInitialized = false;

/*===========================================================================*/
/*                    RANDOM NUMBER GENERATOR                                 */
/*===========================================================================*/
/**
 * @brief   Hàm RNG callback cho micro-ecc
 *
 * @param[out] dest   Buffer nhận random bytes
 * @param[in]  size   Số bytes cần tạo
 *
 * @return  1 nếu thành công, 0 nếu thất bại
 *
 * @warning Đây là RNG đơn giản cho demo!
 *          Trong ECU thực, PHẢI dùng TRNG (True Random Number Generator)
 *          từ hardware hoặc HSM.
 */
static int Crypto_RNG_Function(uint8_t *dest, unsigned size)
{
  unsigned i;
  static uint32_t seed = 0x12345678; /* Fixed seed for demo on bare-metal */

  /* Tạo random bytes bằng LCG đơn giản */
  for (i = 0; i < size; i++)
  {
    seed = (1103515245 * seed + 12345);
    dest[i] = (uint8_t)((seed >> 16) & 0xFF);
  }

  return 1; /* Success */
}

/*===========================================================================*/
/*                    INITIALIZATION                                          */
/*===========================================================================*/
/**
 * @brief   Khởi tạo Crypto ECDSA module
 * @details Được gọi tự động khi cần, không cần gọi manual
 */
static void Crypto_ECDSA_InitModule(void)
{
  static bool initialized = false;

  if (!initialized)
  {
    /* Clear tất cả key slots */
    memset(keySlots, 0, sizeof(keySlots));

    /* Set RNG function cho micro-ecc */
    uECC_set_rng(Crypto_RNG_Function);

    initialized = true;
  }
}

/*===========================================================================*/
/*              HÀM PUBLIC: CRYPTO_ECDSA_GENERATEKEYPAIR                      */
/*===========================================================================*/
Std_ReturnType Crypto_ECDSA_GenerateKeyPair(Crypto_ECDSA_KeyPairType *keyPair)
{
  uint8 publicKey[64]; /* X (32) + Y (32) concatenated */
  int result;
  const struct uECC_Curve_t *curve;

  /* Khởi tạo module nếu chưa */
  Crypto_ECDSA_InitModule();

  /* Kiểm tra tham số */
  if (keyPair == NULL_PTR)
  {
    return E_NOT_OK;
  }

  /* Clear output */
  memset(keyPair, 0, sizeof(Crypto_ECDSA_KeyPairType));

  /* Lấy curve P-256 */
  curve = uECC_secp256r1();

  /*-----------------------------------------------------------------------
   * TẠO KEY PAIR:
   * - Private key: Số ngẫu nhiên d trong [1, n-1]
   * - Public key: Q = d × G (point multiplication)
   *
   * micro-ecc trả về public key dạng uncompressed: X || Y (64 bytes)
   *-----------------------------------------------------------------------*/
  result = uECC_make_key(publicKey, keyPair->privateKey, curve);

  if (result != 1)
  {
    /* Key generation failed */
    return E_NOT_OK;
  }

  /* Tách X và Y từ public key */
  memcpy(keyPair->publicKeyX, publicKey, CRYPTO_ECDSA_P256_KEY_SIZE);
  memcpy(keyPair->publicKeyY, publicKey + CRYPTO_ECDSA_P256_KEY_SIZE,
         CRYPTO_ECDSA_P256_KEY_SIZE);

  keyPair->isValid = true;

  return E_OK;
}

/*===========================================================================*/
/*              HÀM PUBLIC: CRYPTO_ECDSA_SETPRIVATEKEY                        */
/*===========================================================================*/
Std_ReturnType Crypto_ECDSA_SetPrivateKey(uint32 keyId, const uint8 *privateKey,
                                          uint32 keyLength)
{
  uint8 publicKey[64];
  const struct uECC_Curve_t *curve;

  /* Khởi tạo module nếu chưa */
  Crypto_ECDSA_InitModule();

  /* Kiểm tra tham số */
  if (keyId >= CRYPTO_MAX_KEY_SLOTS)
  {
    return E_NOT_OK;
  }

  if (privateKey == NULL_PTR)
  {
    return E_NOT_OK;
  }

  if (keyLength != CRYPTO_ECDSA_P256_KEY_SIZE)
  {
    return (Std_ReturnType)CRYPTO_E_KEY_SIZE_MISMATCH;
  }

  /* Lấy curve P-256 */
  curve = uECC_secp256r1();

  /* Lưu private key */
  memcpy(keySlots[keyId].privateKey, privateKey, CRYPTO_ECDSA_P256_KEY_SIZE);
  keySlots[keyId].hasPrivateKey = true;

  /*-----------------------------------------------------------------------
   * Tự động tính public key từ private key: Q = d × G
   * Điều này đảm bảo private và public luôn khớp nhau
   *-----------------------------------------------------------------------*/
  if (uECC_compute_public_key(privateKey, publicKey, curve) == 1)
  {
    memcpy(keySlots[keyId].publicKeyX, publicKey, CRYPTO_ECDSA_P256_KEY_SIZE);
    memcpy(keySlots[keyId].publicKeyY, publicKey + CRYPTO_ECDSA_P256_KEY_SIZE,
           CRYPTO_ECDSA_P256_KEY_SIZE);
    keySlots[keyId].hasPublicKey = true;
  }

  return E_OK;
}

/*===========================================================================*/
/*              HÀM PUBLIC: CRYPTO_ECDSA_SETPUBLICKEY                         */
/*===========================================================================*/
Std_ReturnType Crypto_ECDSA_SetPublicKey(uint32 keyId, const uint8 *publicKeyX,
                                         const uint8 *publicKeyY,
                                         uint32 keyLength)
{
  /* Khởi tạo module nếu chưa */
  Crypto_ECDSA_InitModule();

  /* Kiểm tra tham số */
  if (keyId >= CRYPTO_MAX_KEY_SLOTS)
  {
    return E_NOT_OK;
  }

  if ((publicKeyX == NULL_PTR) || (publicKeyY == NULL_PTR))
  {
    return E_NOT_OK;
  }

  if (keyLength != CRYPTO_ECDSA_P256_KEY_SIZE)
  {
    return (Std_ReturnType)CRYPTO_E_KEY_SIZE_MISMATCH;
  }

  /* Lưu public key */
  memcpy(keySlots[keyId].publicKeyX, publicKeyX, CRYPTO_ECDSA_P256_KEY_SIZE);
  memcpy(keySlots[keyId].publicKeyY, publicKeyY, CRYPTO_ECDSA_P256_KEY_SIZE);
  keySlots[keyId].hasPublicKey = true;

  return E_OK;
}

/*===========================================================================*/
/*              HÀM PUBLIC: CRYPTO_ECDSA_SIGN                                 */
/*===========================================================================*/
Std_ReturnType Crypto_ECDSA_Sign(uint32 keyId, const uint8 *digest,
                                 uint32 digestLength, uint8 *signature,
                                 uint32 *signatureLength)
{
  int result;
  const struct uECC_Curve_t *curve;

  /* Khởi tạo module nếu chưa */
  Crypto_ECDSA_InitModule();

  /* Kiểm tra tham số */
  if (keyId >= CRYPTO_MAX_KEY_SLOTS)
  {
    return E_NOT_OK;
  }

  if ((digest == NULL_PTR) || (signature == NULL_PTR) ||
      (signatureLength == NULL_PTR))
  {
    return E_NOT_OK;
  }

  if (digestLength != CRYPTO_SHA256_DIGEST_SIZE)
  {
    return E_NOT_OK;
  }

  if (*signatureLength < CRYPTO_ECDSA_P256_SIG_SIZE)
  {
    return (Std_ReturnType)CRYPTO_E_SMALL_BUFFER;
  }

  /* Kiểm tra key đã được set */
  if (!keySlots[keyId].hasPrivateKey)
  {
    return (Std_ReturnType)CRYPTO_E_KEY_NOT_VALID;
  }

  /* Lấy curve P-256 */
  curve = uECC_secp256r1();

  /*-----------------------------------------------------------------------
   * ECDSA SIGN:
   * 1. Chọn k ngẫu nhiên
   * 2. Tính (R, S) từ hash và private key
   *
   * Output signature = R (32 bytes) || S (32 bytes)
   *-----------------------------------------------------------------------*/
  result = uECC_sign(keySlots[keyId].privateKey, /* Private key d */
                     digest,                     /* Hash của message */
                     digestLength,               /* 32 bytes */
                     signature,                  /* Output: R || S */
                     curve);

  if (result != 1)
  {
    return E_NOT_OK;
  }

  *signatureLength = CRYPTO_ECDSA_P256_SIG_SIZE;

  return E_OK;
}

/*===========================================================================*/
/*              HÀM PUBLIC: CRYPTO_ECDSA_VERIFY                               */
/*===========================================================================*/
Std_ReturnType Crypto_ECDSA_Verify(uint32 keyId, const uint8 *digest,
                                   uint32 digestLength, const uint8 *signature,
                                   uint32 signatureLength,
                                   Crypto_VerifyResultType *verifyResult)
{
  uint8 publicKey[64]; /* X || Y concatenated cho micro-ecc */
  int result;
  const struct uECC_Curve_t *curve;

  /* Khởi tạo module nếu chưa */
  Crypto_ECDSA_InitModule();

  /* Kiểm tra tham số */
  if (keyId >= CRYPTO_MAX_KEY_SLOTS)
  {
    return E_NOT_OK;
  }

  if ((digest == NULL_PTR) || (signature == NULL_PTR) ||
      (verifyResult == NULL_PTR))
  {
    return E_NOT_OK;
  }

  if (digestLength != CRYPTO_SHA256_DIGEST_SIZE)
  {
    return E_NOT_OK;
  }

  if (signatureLength != CRYPTO_ECDSA_P256_SIG_SIZE)
  {
    return E_NOT_OK;
  }

  /* Kiểm tra public key đã được set */
  if (!keySlots[keyId].hasPublicKey)
  {
    return (Std_ReturnType)CRYPTO_E_KEY_NOT_VALID;
  }

  /* Lấy curve P-256 */
  curve = uECC_secp256r1();

  /* Tạo public key format cho micro-ecc: X || Y */
  memcpy(publicKey, keySlots[keyId].publicKeyX, CRYPTO_ECDSA_P256_KEY_SIZE);
  memcpy(publicKey + CRYPTO_ECDSA_P256_KEY_SIZE, keySlots[keyId].publicKeyY,
         CRYPTO_ECDSA_P256_KEY_SIZE);

  /*-----------------------------------------------------------------------
   * ECDSA VERIFY:
   * 1. Tính w = S^(-1) mod n
   * 2. Tính u1 = hash × w mod n
   * 3. Tính u2 = R × w mod n
   * 4. Tính P = u1 × G + u2 × Q
   * 5. So sánh R với Px mod n
   *
   * Nếu khớp → signature valid
   * Nếu không khớp → signature invalid (message có thể bị sửa đổi)
   *-----------------------------------------------------------------------*/
  result = uECC_verify(publicKey,    /* Public key Q = (X, Y) */
                       digest,       /* Hash của message */
                       digestLength, /* 32 bytes */
                       signature,    /* Signature = R || S */
                       curve);

  if (result == 1)
  {
    *verifyResult = CRYPTO_E_VER_OK;
  }
  else
  {
    *verifyResult = CRYPTO_E_VER_NOT_OK;
  }

  return E_OK;
}

/*===========================================================================*/
/*              HÀM PUBLIC: CRYPTO_ECDSA_GETPUBLICKEY                         */
/*===========================================================================*/
Std_ReturnType Crypto_ECDSA_GetPublicKey(uint32 keyId, uint8 *publicKeyX,
                                         uint8 *publicKeyY, uint32 keyLength)
{
  uint8 publicKey[64];
  const struct uECC_Curve_t *curve;

  /* Khởi tạo module nếu chưa */
  Crypto_ECDSA_InitModule();

  /* Kiểm tra tham số */
  if (keyId >= CRYPTO_MAX_KEY_SLOTS)
  {
    return E_NOT_OK;
  }

  if ((publicKeyX == NULL_PTR) || (publicKeyY == NULL_PTR))
  {
    return E_NOT_OK;
  }

  if (keyLength != CRYPTO_ECDSA_P256_KEY_SIZE)
  {
    return (Std_ReturnType)CRYPTO_E_KEY_SIZE_MISMATCH;
  }

  /* Kiểm tra private key đã được set */
  if (!keySlots[keyId].hasPrivateKey)
  {
    return (Std_ReturnType)CRYPTO_E_KEY_NOT_VALID;
  }

  /* Lấy curve P-256 */
  curve = uECC_secp256r1();

  /* Tính public key từ private key: Q = d × G */
  if (uECC_compute_public_key(keySlots[keyId].privateKey, publicKey, curve) !=
      1)
  {
    return E_NOT_OK;
  }

  /* Tách X và Y */
  memcpy(publicKeyX, publicKey, CRYPTO_ECDSA_P256_KEY_SIZE);
  memcpy(publicKeyY, publicKey + CRYPTO_ECDSA_P256_KEY_SIZE,
         CRYPTO_ECDSA_P256_KEY_SIZE);

  return E_OK;
}
