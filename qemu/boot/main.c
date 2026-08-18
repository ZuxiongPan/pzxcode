#include <stdint.h>

#define UART_BASE 0x00400000
#define UART_DR (*(volatile uint32_t *)(UART_BASE + 0x0))
#define UART_FR (*(volatile uint32_t *)(UART_BASE + 0x18))
#define UART_FR_TXFF (1 << 5)

#define SD_BASE 0x00500000
#define SD_POWER (*(volatile uint32_t *)(SD_BASE + 0x0))
#define SD_CLOCK (*(volatile uint32_t *)(SD_BASE + 0x4))
#define SD_ARG (*(volatile uint32_t *)(SD_BASE + 0x8))
#define SD_CMD (*(volatile uint32_t *)(SD_BASE + 0xc))
#define SD_RESP0 (*(volatile uint32_t *)(SD_BASE + 0x14))
#define SD_DATATIMER (*(volatile uint32_t *)(SD_BASE + 0x24))
#define SD_DATALEN (*(volatile uint32_t *)(SD_BASE + 0x28))
#define SD_DATACTRL (*(volatile uint32_t *)(SD_BASE + 0x2c))
#define SD_STATUS (*(volatile uint32_t *)(SD_BASE + 0x34))
#define SD_FIFO (*(volatile uint32_t *)(SD_BASE + 0x80))

void uart_putc(char ch)
{
    while ((UART_FR & UART_FR_TXFF) != 0)
    {
        asm volatile("nop");
    }
    UART_DR = ch;
}

void uart_puts(const char *str)
{
    while (*str)
    {
        uart_putc(*str++);
    }
}

void sd_send_cmd(uint32_t cmd_idx, uint32_t arg, uint32_t expected_resp)
{
    SD_ARG = arg;
    uint32_t cmd_val = cmd_idx | (1 << 10);
    if (expected_resp)
    {
        cmd_val |= (1 << 6);
    }

    SD_CMD = cmd_val;
    while (SD_STATUS & (1 << 11))
    {
        // do nothing
    }
}

void load_form_sd(void)
{
    uart_puts("Init SD...\n");
    SD_POWER = 0xbf;
    SD_CLOCK = 0x1ff | (1 << 8);

    sd_send_cmd(0, 0, 0);
    sd_send_cmd(8, 0x1aa, 1);

    do {
        sd_send_cmd(55, 0, 1);
        sd_send_cmd(41, 0x51ff8000, 1);
    } while ((SD_RESP0 & (1U << 31)) == 0);

    sd_send_cmd(2, 0, 1);
    sd_send_cmd(3, 0, 1);
    uint32_t rca = SD_RESP0 & 0xffff0000;
    sd_send_cmd(7, rca, 1);
    sd_send_cmd(16, 512, 1);

    uart_puts("Loading code from sd to sram...\n");
    SD_DATATIMER = 0xffffffff;
    SD_DATALEN = 4096;

    SD_DATACTRL = 1 | (1 << 1) | (9 << 4);
    sd_send_cmd(18, 0, 1);

    uint32_t *dest = (uint32_t *)0x00100000;
    int words_to_read = 4096 / 4;
    while (words_to_read > 0)
    {
        if ((SD_STATUS & (1 << 19)) == 0)
        {
            *dest++ = SD_FIFO;
            words_to_read--;
        }
    }
    sd_send_cmd(12, 0, 1);
    uart_puts("Code loaded to sram success.\n");
}

int main(void)
{
    uart_puts("Boot MROM\n");
    
    load_form_sd();

    uart_puts("Start Run Loader...\n");
    
    return 0x00100000;
}

