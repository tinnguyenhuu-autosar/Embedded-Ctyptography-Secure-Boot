/*******************************************************************************
 * @file    uart_log.c
 * @brief   BSP – UART Logging + LED Implementation
 * @details USART1 PA9 TX @ 115200 + LED PC13 (BluePill)
 *
 * @author  HALA Academy
 * @version 1.0.0
 ******************************************************************************/

#include "uart_log.h"
#include "stm32f10x_rcc.h"
#include "stm32f10x_gpio.h"
#include "stm32f10x_usart.h"

/*===========================================================================*/
/*                    UART INIT / PRINT                                       */
/*===========================================================================*/

void Log_Init(void) {
    /* Enable clocks: USART1 + GPIOA */
    RCC_APB2PeriphClockCmd(RCC_APB2Periph_USART1 |
                           RCC_APB2Periph_GPIOA, ENABLE);

    /* PA9 = USART1_TX: Alternate function push-pull */
    GPIO_InitTypeDef gpio;
    gpio.GPIO_Pin   = GPIO_Pin_9;
    gpio.GPIO_Mode  = GPIO_Mode_AF_PP;
    gpio.GPIO_Speed = GPIO_Speed_50MHz;
    GPIO_Init(GPIOA, &gpio);

    /* PA10 = USART1_RX: Input floating (optional) */
    gpio.GPIO_Pin  = GPIO_Pin_10;
    gpio.GPIO_Mode = GPIO_Mode_IN_FLOATING;
    GPIO_Init(GPIOA, &gpio);

    /* USART1 config: 115200, 8N1 */
    USART_InitTypeDef uart;
    uart.USART_BaudRate            = 115200;
    uart.USART_WordLength          = USART_WordLength_8b;
    uart.USART_StopBits            = USART_StopBits_1;
    uart.USART_Parity              = USART_Parity_No;
    uart.USART_HardwareFlowControl = USART_HardwareFlowControl_None;
    uart.USART_Mode                = USART_Mode_Tx | USART_Mode_Rx;
    USART_Init(USART1, &uart);
    USART_Cmd(USART1, ENABLE);
}

void Log_Print(const char *str) {
    while (*str) {
        while (USART_GetFlagStatus(USART1, USART_FLAG_TXE) == RESET)
            ;
        USART_SendData(USART1, (uint16_t)*str++);
    }
}

/**
 * @brief  Helper: print single hex nibble
 */
static void print_nibble(uint8 nibble) {
    char c = (nibble < 10u) ? ('0' + nibble) : ('a' + nibble - 10u);
    while (USART_GetFlagStatus(USART1, USART_FLAG_TXE) == RESET)
        ;
    USART_SendData(USART1, (uint16_t)c);
}

void Log_PrintHex(const char *prefix, const uint8 *data, uint32 len) {
    Log_Print(prefix);
    for (uint32 i = 0u; i < len; i++) {
        print_nibble((data[i] >> 4u) & 0x0Fu);
        print_nibble(data[i] & 0x0Fu);
    }
    Log_Print("\r\n");
}

void Log_PrintUint(const char *prefix, uint32 value) {
    char buf[12]; /* max uint32 = 4294967295 = 10 digits + null */
    int pos = 10;
    buf[11] = '\0';

    if (value == 0u) {
        buf[pos--] = '0';
    } else {
        while (value > 0u) {
            buf[pos--] = '0' + (char)(value % 10u);
            value /= 10u;
        }
    }

    Log_Print(prefix);
    Log_Print(&buf[pos + 1]);
}

/*===========================================================================*/
/*                    LED PC13                                                */
/*===========================================================================*/

void Led_Init(void) {
    RCC_APB2PeriphClockCmd(RCC_APB2Periph_GPIOC, ENABLE);

    GPIO_InitTypeDef gpio;
    gpio.GPIO_Pin   = GPIO_Pin_13;
    gpio.GPIO_Mode  = GPIO_Mode_Out_PP;
    gpio.GPIO_Speed = GPIO_Speed_2MHz;
    GPIO_Init(GPIOC, &gpio);

    /* LED off (PC13 active LOW: HIGH = off) */
    GPIO_SetBits(GPIOC, GPIO_Pin_13);
}

void Led_Toggle(void) {
    if (GPIO_ReadOutputDataBit(GPIOC, GPIO_Pin_13)) {
        GPIO_ResetBits(GPIOC, GPIO_Pin_13); /* ON */
    } else {
        GPIO_SetBits(GPIOC, GPIO_Pin_13);   /* OFF */
    }
}

void Led_On(void) {
    GPIO_ResetBits(GPIOC, GPIO_Pin_13); /* Active LOW */
}

void Led_Off(void) {
    GPIO_SetBits(GPIOC, GPIO_Pin_13);
}

/*===========================================================================*/
/*                    DELAY                                                   */
/*===========================================================================*/

void Delay_ms(volatile uint32 ms) {
    while (ms--) {
        for (volatile uint32 i = 0u; i < 7200u; i++) {
            __asm__("nop");
        }
    }
}
