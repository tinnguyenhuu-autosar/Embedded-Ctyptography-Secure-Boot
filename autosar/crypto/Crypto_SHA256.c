/*******************************************************************************
 * @file    Crypto_SHA256.c
 * @brief   Crypto Driver - SHA-256 Hash Algorithm Implementation
 * @details Triển khai thuật toán SHA-256 theo chuẩn FIPS 180-4
 *
 *
 * @note    THUẬT TOÁN SHA-256 (chi tiết):
 *
 *          1. TIỀN XỬ LÝ (Preprocessing):
 *             - Padding message để độ dài = bội số của 512 bits
 *             - Append bit '1', sau đó append bits '0'
 *             - Append 64-bit độ dài message gốc (big-endian)
 *
 *          2. PHÂN TÍCH (Parsing):
 *             - Chia message đã pad thành các block 512-bit
 *             - Mỗi block = 16 words (mỗi word = 32-bit)
 *
 *          3. XỬ LÝ TỪNG BLOCK:
 *             a) Message Schedule: Mở rộng 16 words → 64 words
 *                W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]
 *
 *             b) 64 Rounds compression:
 *                - Dùng 8 biến làm việc a,b,c,d,e,f,g,h
 *                - Mỗi round: T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
 *                             T2 = Σ0(a) + Maj(a,b,c)
 *                             Cập nhật a,b,c,d,e,f,g,h
 *
 *             c) Cộng kết quả vào hash values H0..H7
 *
 *          4. KẾT QUẢ:
 *             - Nối H0||H1||H2||H3||H4||H5||H6||H7 = 256 bits
 ******************************************************************************/

/*===========================================================================*/
/*                              INCLUDES                                      */
/*===========================================================================*/
#include "Crypto_SHA256.h"
#include <string.h>

/*===========================================================================*/
/*              HẰNG SỐ KHỞI TẠO H0..H7 (Initial Hash Values)                 */
/*===========================================================================*/
/**
 * @brief 8 giá trị hash khởi tạo từ FIPS 180-4 Section 5.3.3
 * @details Đây là 32 bits đầu của phần thập phân căn bậc 2
 *          của 8 số nguyên tố đầu tiên (2, 3, 5, 7, 11, 13, 17, 19)
 */
static const uint32 SHA256_H_INIT[8] = {
    0x6a09e667u, /* H0 - từ √2 */
    0xbb67ae85u, /* H1 - từ √3 */
    0x3c6ef372u, /* H2 - từ √5 */
    0xa54ff53au, /* H3 - từ √7 */
    0x510e527fu, /* H4 - từ √11 */
    0x9b05688cu, /* H5 - từ √13 */
    0x1f83d9abu, /* H6 - từ √17 */
    0x5be0cd19u  /* H7 - từ √19 */
};

/*===========================================================================*/
/*              HẰNG SỐ ROUND K0..K63 (Round Constants)                       */
/*===========================================================================*/
/**
 * @brief 64 hằng số round từ FIPS 180-4 Section 4.2.2
 * @details Đây là 32 bits đầu của phần thập phân căn bậc 3
 *          của 64 số nguyên tố đầu tiên (2, 3, 5, ..., 311)
 */
static const uint32 SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

/*===========================================================================*/
/*              MACRO CÁC PHÉP TOÁN CƠ BẢN                                    */
/*===========================================================================*/

/**
 * @brief Rotate Right (ROTR) - Xoay phải n bits
 * @details ROTR^n(x) = (x >> n) | (x << (32-n))
 */
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32u - (n))))

/**
 * @brief Shift Right (SHR) - Dịch phải n bits
 * @details SHR^n(x) = x >> n
 */
#define SHR(x, n) ((x) >> (n))

/**
 * @brief Ch(x,y,z) - Choose function
 * @details Ch(x,y,z) = (x AND y) XOR ((NOT x) AND z)
 *          Nếu bit x = 1, chọn bit từ y; nếu x = 0, chọn bit từ z
 */
#define CH(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))

/**
 * @brief Maj(x,y,z) - Majority function
 * @details Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)
 *          Kết quả là bit xuất hiện nhiều nhất (đa số) trong 3 input
 */
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/**
 * @brief Σ0(x) - Big Sigma 0 (dùng trong compression)
 * @details Σ0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
 */
#define BSIG0(x) (ROTR((x), 2u) ^ ROTR((x), 13u) ^ ROTR((x), 22u))

/**
 * @brief Σ1(x) - Big Sigma 1 (dùng trong compression)
 * @details Σ1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
 */
#define BSIG1(x) (ROTR((x), 6u) ^ ROTR((x), 11u) ^ ROTR((x), 25u))

/**
 * @brief σ0(x) - Small Sigma 0 (dùng trong message schedule)
 * @details σ0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
 */
#define SSIG0(x) (ROTR((x), 7u) ^ ROTR((x), 18u) ^ SHR((x), 3u))

/**
 * @brief σ1(x) - Small Sigma 1 (dùng trong message schedule)
 * @details σ1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
 */
#define SSIG1(x) (ROTR((x), 17u) ^ ROTR((x), 19u) ^ SHR((x), 10u))

/*===========================================================================*/
/*              HÀM NỘI BỘ: XỬ LÝ MỘT BLOCK 512-BIT                           */
/*===========================================================================*/
/**
 * @brief   Xử lý một block 512-bit (64 bytes)
 *
 * @param[in,out] state  Mảng 8 giá trị hash H0..H7
 * @param[in]     block  Block dữ liệu 64 bytes
 *
 * @details Đây là phần lõi của SHA-256:
 *          1. Tạo message schedule W[0..63] từ 16 words input
 *          2. Chạy 64 rounds compression
 *          3. Cộng kết quả vào state
 */
static void Crypto_SHA256_ProcessBlock(uint32 *state, const uint8 *block)
{
  uint32 W[64];                  /* Message schedule */
  uint32 a, b, c, d, e, f, g, h; /* 8 working variables */
  uint32 T1, T2;
  uint32 t;

  /*-----------------------------------------------------------------------
   * BƯỚC 1: Chuẩn bị Message Schedule W[0..63]
   *-----------------------------------------------------------------------*/

  /* W[0..15]: Copy 16 words từ block (big-endian → host) */
  for (t = 0u; t < 16u; t++)
  {
    W[t] = ((uint32)block[t * 4u] << 24u) |
           ((uint32)block[t * 4u + 1u] << 16u) |
           ((uint32)block[t * 4u + 2u] << 8u) | ((uint32)block[t * 4u + 3u]);
  }

  /* W[16..63]: Mở rộng theo công thức
   * W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]
   */
  for (t = 16u; t < 64u; t++)
  {
    W[t] = SSIG1(W[t - 2u]) + W[t - 7u] + SSIG0(W[t - 15u]) + W[t - 16u];
  }

  /*-----------------------------------------------------------------------
   * BƯỚC 2: Khởi tạo 8 working variables từ state hiện tại
   *-----------------------------------------------------------------------*/
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];
  f = state[5];
  g = state[6];
  h = state[7];

  /*-----------------------------------------------------------------------
   * BƯỚC 3: 64 rounds compression
   *
   * Mỗi round:
   *   T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]
   *   T2 = Σ0(a) + Maj(a,b,c)
   *   h = g
   *   g = f
   *   f = e
   *   e = d + T1
   *   d = c
   *   c = b
   *   b = a
   *   a = T1 + T2
   *-----------------------------------------------------------------------*/
  for (t = 0u; t < 64u; t++)
  {
    T1 = h + BSIG1(e) + CH(e, f, g) + SHA256_K[t] + W[t];
    T2 = BSIG0(a) + MAJ(a, b, c);

    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
  }

  /*-----------------------------------------------------------------------
   * BƯỚC 4: Cộng kết quả vào state (mod 2^32)
   *-----------------------------------------------------------------------*/
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

/*===========================================================================*/
/*              HÀM PUBLIC: CRYPTO_SHA256_INIT                                */
/*===========================================================================*/
Std_ReturnType Crypto_SHA256_Init(Crypto_SHA256_ContextType *ctx)
{
  /* Kiểm tra tham số */
  if (ctx == NULL_PTR)
  {
    return E_NOT_OK;
  }

  /* Khởi tạo state với 8 hằng số từ FIPS 180-4 */
  ctx->state[0] = SHA256_H_INIT[0];
  ctx->state[1] = SHA256_H_INIT[1];
  ctx->state[2] = SHA256_H_INIT[2];
  ctx->state[3] = SHA256_H_INIT[3];
  ctx->state[4] = SHA256_H_INIT[4];
  ctx->state[5] = SHA256_H_INIT[5];
  ctx->state[6] = SHA256_H_INIT[6];
  ctx->state[7] = SHA256_H_INIT[7];

  /* Reset bit count và buffer */
  ctx->bitCount = 0u;
  ctx->bufferLen = 0u;
  memset(ctx->buffer, 0, CRYPTO_SHA256_BLOCK_SIZE);

  return E_OK;
}

/*===========================================================================*/
/*              HÀM PUBLIC: CRYPTO_SHA256_UPDATE                              */
/*===========================================================================*/
Std_ReturnType Crypto_SHA256_Update(Crypto_SHA256_ContextType *ctx,
                                    const uint8 *data, uint32 length)
{
  uint32 i;
  uint32 remaining;
  uint32 toCopy;

  /* Kiểm tra tham số */
  if (ctx == NULL_PTR)
  {
    return E_NOT_OK;
  }

  /* Cho phép data = NULL nếu length = 0 */
  if ((data == NULL_PTR) && (length > 0u))
  {
    return E_NOT_OK;
  }

  /* Xử lý từng byte */
  for (i = 0u; i < length;)
  {
    /* Tính số bytes có thể copy vào buffer */
    remaining = CRYPTO_SHA256_BLOCK_SIZE - ctx->bufferLen;
    toCopy = (length - i) < remaining ? (length - i) : remaining;

    /* Copy vào buffer */
    memcpy(&ctx->buffer[ctx->bufferLen], &data[i], toCopy);
    ctx->bufferLen += toCopy;
    i += toCopy;

    /* Nếu buffer đầy (64 bytes), xử lý block */
    if (ctx->bufferLen == CRYPTO_SHA256_BLOCK_SIZE)
    {
      Crypto_SHA256_ProcessBlock(ctx->state, ctx->buffer);
      ctx->bufferLen = 0u;
    }
  }

  /* Cập nhật tổng số bits */
  ctx->bitCount += ((uint64)length * 8u);

  return E_OK;
}

/*===========================================================================*/
/*              HÀM PUBLIC: CRYPTO_SHA256_FINISH                              */
/*===========================================================================*/
Std_ReturnType Crypto_SHA256_Finish(Crypto_SHA256_ContextType *ctx,
                                    uint8 *digest, uint32 *digestLength)
{
  uint32 i;
  uint8 padBlock[CRYPTO_SHA256_BLOCK_SIZE];
  uint32 padLen;
  uint64 totalBits;

  /* Kiểm tra tham số */
  if ((ctx == NULL_PTR) || (digest == NULL_PTR) || (digestLength == NULL_PTR))
  {
    return E_NOT_OK;
  }

  /* Kiểm tra buffer đủ lớn */
  if (*digestLength < CRYPTO_SHA256_DIGEST_SIZE)
  {
    return (Std_ReturnType)CRYPTO_E_SMALL_BUFFER;
  }

  /*-----------------------------------------------------------------------
   * PADDING theo FIPS 180-4 Section 5.1.1:
   * 1. Append bit '1' (0x80)
   * 2. Append bits '0' sao cho tổng length ≡ 448 (mod 512)
   * 3. Append 64-bit big-endian của tổng số bits message
   *-----------------------------------------------------------------------*/

  totalBits = ctx->bitCount;

  /* Tính độ dài padding cần thiết:
   * Cần: bufferLen + padLen ≡ 56 (mod 64)
   * 56 bytes = 448 bits, để dành 8 bytes cho length
   */
  if (ctx->bufferLen < 56u)
  {
    padLen = 56u - ctx->bufferLen;
  }
  else
  {
    /* Cần thêm block mới */
    padLen = 64u + 56u - ctx->bufferLen;
  }

  /* Tạo padding: 0x80 theo sau là các 0x00 */
  memset(padBlock, 0, sizeof(padBlock));
  padBlock[0] = 0x80u;

  /* Thêm padding (trừ byte 0x80 đã có) */
  Crypto_SHA256_Update(ctx, padBlock, 1u); /* Byte 0x80 */
  if (padLen > 1u)
  {
    Crypto_SHA256_Update(ctx, &padBlock[1], padLen - 1u); /* Các byte 0x00 */
  }

  /* Thêm 64-bit length (big-endian) */
  padBlock[0] = (uint8)(totalBits >> 56u);
  padBlock[1] = (uint8)(totalBits >> 48u);
  padBlock[2] = (uint8)(totalBits >> 40u);
  padBlock[3] = (uint8)(totalBits >> 32u);
  padBlock[4] = (uint8)(totalBits >> 24u);
  padBlock[5] = (uint8)(totalBits >> 16u);
  padBlock[6] = (uint8)(totalBits >> 8u);
  padBlock[7] = (uint8)(totalBits);

  Crypto_SHA256_Update(ctx, padBlock, 8u);

  /*-----------------------------------------------------------------------
   * Xuất digest (big-endian)
   *-----------------------------------------------------------------------*/
  for (i = 0u; i < 8u; i++)
  {
    digest[i * 4u] = (uint8)(ctx->state[i] >> 24u);
    digest[i * 4u + 1u] = (uint8)(ctx->state[i] >> 16u);
    digest[i * 4u + 2u] = (uint8)(ctx->state[i] >> 8u);
    digest[i * 4u + 3u] = (uint8)(ctx->state[i]);
  }

  *digestLength = CRYPTO_SHA256_DIGEST_SIZE;

  return E_OK;
}

/*===========================================================================*/
/*              HÀM PUBLIC: CRYPTO_SHA256_CALCULATE                           */
/*===========================================================================*/
Std_ReturnType Crypto_SHA256_Calculate(const uint8 *data, uint32 dataLength,
                                       uint8 *digest, uint32 *digestLength)
{
  Crypto_SHA256_ContextType ctx;
  Std_ReturnType result;

  /* Kiểm tra tham số */
  if ((digest == NULL_PTR) || (digestLength == NULL_PTR))
  {
    return E_NOT_OK;
  }

  /* Cho phép data = NULL nếu dataLength = 0 (hash empty string) */
  if ((data == NULL_PTR) && (dataLength > 0u))
  {
    return E_NOT_OK;
  }

  /* Init */
  result = Crypto_SHA256_Init(&ctx);
  if (result != E_OK)
  {
    return result;
  }

  /* Update */
  if (dataLength > 0u)
  {
    result = Crypto_SHA256_Update(&ctx, data, dataLength);
    if (result != E_OK)
    {
      return result;
    }
  }

  /* Finish */
  result = Crypto_SHA256_Finish(&ctx, digest, digestLength);

  return result;
}
