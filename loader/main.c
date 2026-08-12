#include <stdint.h>

#define UART_BASE 0x00200000
#define UART_DR (*(volatile uint32_t *)(UART_BASE + 0x0))
#define UART_FR (*(volatile uint32_t *)(UART_BASE + 0x18))
#define UART_FR_TXFF (1 << 5)

#define SD_BASE 0x00300000
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

char hex_char(uint32_t val)
{
    if (val < 10)
    {
        return val + '0';
    }
    else
    {
        return val - 10 + 'a';
    }
}

void memory_hexdump(const char *addr, int len)
{
    int i = 0;
    char byte = 0;

    while (i < len)
    {
        byte = addr[i];
        uart_putc(hex_char(byte >> 4));
        uart_putc(hex_char(byte & 0xf));
        uart_putc(' ');
        if ((i + 1) % 16 == 0)
        {
            uart_putc('\r');
            uart_putc('\n');
        }
        i++;
    }

    if (len % 16 != 0)
    {
        uart_putc('\r');
        uart_putc('\n');
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


void dram_init(void)
{
    uart_puts("Init DRAM...\n");
    uart_puts("Init DRAM success.\n");
}

void load_uboot_form_sd(void)
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

    uart_puts("Loading code from sd to dram...\n");
    SD_DATATIMER = 0xffffffff;
    SD_DATALEN = 512;

    sd_send_cmd(17, 0, 1);
    SD_DATACTRL = 1 | (1 << 1) | (9 << 4);

    uint32_t *dest = (uint32_t *)0x80000000;
    int words_to_read = 512 / 4;
    while (words_to_read > 0)
    {
        if ((SD_STATUS & (1 << 19)) == 0)
        {
            *dest++ = SD_FIFO;
            words_to_read--;
        }
    }
    uart_puts("Code loaded to dram success.\n");
}

int main(void)
{
    uart_puts("Boot SRAM\n");

    dram_init();
    
    load_uboot_form_sd();

    memory_hexdump((char *)0x80000000, 1024);

    uart_puts("Start Run Uboot...\n");

    while (1)
    {
        asm volatile("nop");
    }
    
    return 0x00080000;
}

