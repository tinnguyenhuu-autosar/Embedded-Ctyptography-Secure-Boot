/*******************************************************************************
 * @file    Crypto_SHA256.h
 * @brief   Crypto Driver - SHA-256 Hash Algorithm Interface
 * @details API cho thuật toán hash SHA-256 theo FIPS 180-4
 *          Hỗ trợ cả single call và streaming mode
 *
 * @note    Thuật toán SHA-256:
 *          - Input: Message có độ dài bất kỳ
 *          - Output: Digest 256-bit (32 bytes)
 *          - Block size: 512-bit (64 bytes)
 *          - Số rounds: 64
 ******************************************************************************/

#ifndef CRYPTO_SHA256_H
#define CRYPTO_SHA256_H

/*===========================================================================*/
/*                              INCLUDES                                      */
/*===========================================================================*/
#include "Crypto_Types.h"

/*===========================================================================*/
/*                    SHA-256 CONTEXT STRUCTURE                               */
/*===========================================================================*/
/**
 * @brief Context lưu trạng thái trung gian khi hash theo kiểu streaming
 *
 * @details Khi hash dữ liệu lớn (ví dụ: firmware nhiều MB), không thể
 *          load toàn bộ vào RAM. Thay vào đó, ta hash từng chunk:
 *
 *          1. Init: Khởi tạo state với H0..H7
 *          2. Update: Thêm từng chunk, xử lý khi đủ 64 bytes
 *          3. Finish: Padding và xuất digest
 *
 *          Context lưu trạng thái giữa các lần gọi Update.
 */
typedef struct
{
  /**
   * @brief 8 giá trị hash trung gian H0..H7 (256 bits tổng)
   * @note  Khởi tạo với các hằng số từ FIPS 180-4
   *        Cập nhật sau mỗi block 512-bit được xử lý
   */
  uint32 state[8];

  /**
   * @brief Tổng số bits đã xử lý (cần cho padding)
   * @note  Dùng uint64 vì message có thể rất lớn (>4GB)
   */
  uint64 bitCount;

  /**
   * @brief Buffer chứa dữ liệu chưa đủ 1 block (64 bytes)
   * @note  Khi buffer đầy 64 bytes, sẽ được xử lý và clear
   */
  uint8 buffer[CRYPTO_SHA256_BLOCK_SIZE];

  /**
   * @brief Số bytes hiện có trong buffer
   */
  uint32 bufferLen;

} Crypto_SHA256_ContextType;

/*===========================================================================*/
/*                    SHA-256 API FUNCTIONS                                   */
/*===========================================================================*/

/**
 * @brief   Khởi tạo context SHA-256 với các giá trị ban đầu
 *
 * @param[out] ctx  Con trỏ đến context cần khởi tạo
 *
 * @return  E_OK     - Khởi tạo thành công
 * @return  E_NOT_OK - ctx là NULL
 *
 * @details Khởi tạo state[0..7] với 8 hằng số từ FIPS 180-4:
 *          - H0 = 0x6a09e667 (căn bậc 2 của 2)
 *          - H1 = 0xbb67ae85 (căn bậc 2 của 3)
 *          - H2 = 0x3c6ef372 (căn bậc 2 của 5)
 *          - H3 = 0xa54ff53a (căn bậc 2 của 7)
 *          - H4 = 0x510e527f (căn bậc 2 của 11)
 *          - H5 = 0x9b05688c (căn bậc 2 của 13)
 *          - H6 = 0x1f83d9ab (căn bậc 2 của 17)
 *          - H7 = 0x5be0cd19 (căn bậc 2 của 19)
 *
 * @note    Phải gọi trước Crypto_SHA256_Update
 *
 * @code
 * Crypto_SHA256_ContextType ctx;
 * if (Crypto_SHA256_Init(&ctx) == E_OK) {
 *     // Context ready for Update
 * }
 * @endcode
 */
Std_ReturnType Crypto_SHA256_Init(Crypto_SHA256_ContextType *ctx);

/**
 * @brief   Thêm dữ liệu vào quá trình hash
 *
 * @param[in,out] ctx     Context đã được Init
 * @param[in]     data    Con trỏ đến dữ liệu cần hash
 * @param[in]     length  Độ dài dữ liệu (bytes)
 *
 * @return  E_OK     - Thêm dữ liệu thành công
 * @return  E_NOT_OK - ctx hoặc data là NULL (khi length > 0)
 *
 * @details Có thể gọi nhiều lần để xử lý dữ liệu lớn theo chunks.
 *          Dữ liệu được buffer cho đến khi đủ 64 bytes để xử lý.
 *
 * @note    - Có thể gọi với length = 0 (không ảnh hưởng gì)
 *          - Context phải đã được Init trước đó
 *
 * @code
 * // Hash firmware theo chunks 4KB
 * uint8 chunk[4096];
 * uint32 bytesRead;
 *
 * Crypto_SHA256_Init(&ctx);
 * while ((bytesRead = ReadChunk(chunk, sizeof(chunk))) > 0) {
 *     Crypto_SHA256_Update(&ctx, chunk, bytesRead);
 * }
 * // Sau đó gọi Finish...
 * @endcode
 */
Std_ReturnType Crypto_SHA256_Update(Crypto_SHA256_ContextType *ctx,
                                    const uint8 *data, uint32 length);

/**
 * @brief   Kết thúc quá trình hash và xuất digest 32 bytes
 *
 * @param[in,out] ctx          Context đã được Init và Update
 * @param[out]    digest       Buffer nhận kết quả hash (tối thiểu 32 bytes)
 * @param[in,out] digestLength [in] Kích thước buffer
 *                             [out] Số bytes thực tế ghi vào (luôn = 32)
 *
 * @return  E_OK                  - Hash thành công
 * @return  E_NOT_OK              - Tham số không hợp lệ
 * @return  CRYPTO_E_SMALL_BUFFER - Buffer < 32 bytes
 *
 * @details Thực hiện padding theo FIPS 180-4:
 *          1. Append bit '1'
 *          2. Append bits '0' cho đến khi length ≡ 448 (mod 512)
 *          3. Append 64-bit big-endian của tổng số bits message
 *
 * @warning Sau khi gọi Finish, context không còn hợp lệ.
 *          Cần Init lại nếu muốn hash message khác.
 *
 * @code
 * uint8 digest[32];
 * uint32 digestLen = sizeof(digest);
 *
 * if (Crypto_SHA256_Finish(&ctx, digest, &digestLen) == E_OK) {
 *     // digest chứa 32 bytes hash
 *     printf("Digest length: %u\n", digestLen); // In ra 32
 * }
 * @endcode
 */
Std_ReturnType Crypto_SHA256_Finish(Crypto_SHA256_ContextType *ctx,
                                    uint8 *digest, uint32 *digestLength);

/**
 * @brief   Hash một message trong một lần gọi (Single Call)
 *
 * @param[in]     data         Dữ liệu cần hash
 * @param[in]     dataLength   Độ dài dữ liệu (bytes)
 * @param[out]    digest       Buffer nhận kết quả (tối thiểu 32 bytes)
 * @param[in,out] digestLength [in] Kích thước buffer
 *                             [out] Số bytes output (32)
 *
 * @return  E_OK     - Hash thành công
 * @return  E_NOT_OK - Lỗi tham số
 *
 * @details Kết hợp Init + Update + Finish trong một lần gọi.
 *          Tiện lợi khi dữ liệu nhỏ, có sẵn toàn bộ trong RAM.
 *
 * @note    Không cần quản lý context bên ngoài.
 *
 * @code
 * const char* msg = "Hello AUTOSAR!";
 * uint8 digest[32];
 * uint32 digestLen = sizeof(digest);
 *
 * Crypto_SHA256_Calculate((const uint8*)msg, strlen(msg), digest, &digestLen);
 * @endcode
 */
Std_ReturnType Crypto_SHA256_Calculate(const uint8 *data, uint32 dataLength, uint8 *digest, uint32 *digestLength);

#endif /* CRYPTO_SHA256_H */
