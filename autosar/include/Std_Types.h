/*******************************************************************************
 * @file    Std_Types.h
 * @brief   AUTOSAR Standard Types Definition
 * @details Định nghĩa các kiểu dữ liệu cơ bản theo chuẩn AUTOSAR
 * 
 * @author  HALA Academy
 * @version 1.0.0
 * @date    2026-01-02
 * 
 * @note    Tuân thủ AUTOSAR Classic Platform R22-11
 ******************************************************************************/

#ifndef STD_TYPES_H
#define STD_TYPES_H

/*===========================================================================*/
/*                              INCLUDES                                      */
/*===========================================================================*/
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*===========================================================================*/
/*                      KIỂU SỐ NGUYÊN KHÔNG DẤU                              */
/*===========================================================================*/
/**
 * @brief Số nguyên không dấu 8-bit (0 đến 255)
 */
typedef uint8_t     uint8;

/**
 * @brief Số nguyên không dấu 16-bit (0 đến 65535)
 */
typedef uint16_t    uint16;

/**
 * @brief Số nguyên không dấu 32-bit (0 đến 4294967295)
 */
typedef uint32_t    uint32;

/**
 * @brief Số nguyên không dấu 64-bit
 */
typedef uint64_t    uint64;

/*===========================================================================*/
/*                      KIỂU SỐ NGUYÊN CÓ DẤU                                 */
/*===========================================================================*/
/**
 * @brief Số nguyên có dấu 8-bit (-128 đến 127)
 */
typedef int8_t      sint8;

/**
 * @brief Số nguyên có dấu 16-bit (-32768 đến 32767)
 */
typedef int16_t     sint16;

/**
 * @brief Số nguyên có dấu 32-bit
 */
typedef int32_t     sint32;

/*===========================================================================*/
/*                      KIỂU TRẢ VỀ CHUẨN                                     */
/*===========================================================================*/
/**
 * @brief Kiểu trả về chuẩn AUTOSAR
 * @details Dùng để báo kết quả thành công/thất bại của các hàm
 */
typedef uint8 Std_ReturnType;

/**
 * @brief Hàm thực hiện thành công
 */
#define E_OK        ((Std_ReturnType)0x00u)

/**
 * @brief Hàm thực hiện thất bại
 */
#define E_NOT_OK    ((Std_ReturnType)0x01u)

/*===========================================================================*/
/*                      MACRO BẬT/TẮT                                         */
/*===========================================================================*/
/**
 * @brief Macro cho trạng thái BẬT
 */
#define STD_ON      (1u)

/**
 * @brief Macro cho trạng thái TẮT
 */
#define STD_OFF     (0u)

/**
 * @brief Con trỏ NULL
 */
#define NULL_PTR    ((void*)0)

/**
 * @brief Macro TRUE cho boolean
 */
#ifndef TRUE
#define TRUE        (1u)
#endif

/**
 * @brief Macro FALSE cho boolean
 */
#ifndef FALSE
#define FALSE       (0u)
#endif

/*===========================================================================*/
/*                      VERSION STRUCTURE                                     */
/*===========================================================================*/
/**
 * @brief Structure chứa thông tin version
 */
typedef struct {
    uint16 vendorID;            /**< ID của vendor */
    uint16 moduleID;            /**< ID của module */
    uint8  sw_major_version;    /**< Major version */
    uint8  sw_minor_version;    /**< Minor version */
    uint8  sw_patch_version;    /**< Patch version */
} Std_VersionInfoType;

#endif /* STD_TYPES_H */
