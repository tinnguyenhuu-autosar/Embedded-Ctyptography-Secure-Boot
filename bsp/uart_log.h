/*******************************************************************************
 * @file    uart_log.h
 * @brief   BSP – UART Logging + LED cho STM32F103 (BluePill)
 * @details Thay thế printf bằng USART1 output (PA9 TX, PA10 RX)
 *          LED PC13 toggle để chỉ trạng thái crypto operations
 *
 * @author  HALA Academy
 * @version 1.0.0
 ******************************************************************************/
#ifndef UART_LOG_H
#define UART_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include "Std_Types.h"

/*===========================================================================*/
/*                    UART LOGGING API                                        */
/*===========================================================================*/

/**
 * @brief  Khởi tạo USART1 @ 115200 baud (PA9 = TX)
 */
void Log_Init(void);

/**
 * @brief  In chuỗi qua UART1 (blocking)
 * @param  str  Chuỗi kết thúc NULL
 */
void Log_Print(const char *str);

/**
 * @brief  In chuỗi hex từ mảng bytes
 * @param  prefix  Tiền tố in trước hex
 * @param  data    Mảng bytes
 * @param  len     Số bytes
 */
void Log_PrintHex(const char *prefix, const uint8 *data, uint32 len);

/**
 * @brief  In số nguyên dạng decimal
 * @param  prefix  Tiền tố
 * @param  value   Giá trị
 */
void Log_PrintUint(const char *prefix, uint32 value);

/*===========================================================================*/
/*                    LED API (PC13 – BluePill onboard)                       */
/*===========================================================================*/

/**
 * @brief  Khởi tạo PC13 output push-pull (LED onboard, active LOW)
 */
void Led_Init(void);

/**
 * @brief  Toggle LED PC13
 */
void Led_Toggle(void);

/**
 * @brief  Bật LED (PC13 = LOW)
 */
void Led_On(void);

/**
 * @brief  Tắt LED (PC13 = HIGH)
 */
void Led_Off(void);

/*===========================================================================*/
/*                    DELAY                                                   */
/*===========================================================================*/

/**
 * @brief  Delay ước lượng milliseconds (polling, không chính xác)
 * @param  ms  Số milliseconds
 */
void Delay_ms(volatile uint32 ms);

#ifdef __cplusplus
}
#endif

#endif /* UART_LOG_H */
