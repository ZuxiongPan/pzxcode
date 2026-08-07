#include <stdint.h>

#define UART_BASE 0x00200000
#define UART_DR (*(volatile uint32_t *)(UART_BASE + 0x0))
#define UART_FR (*(volatile uint32_t *)(UART_BASE + 0x18))
#define UART_FR_TXFF (1 << 5)

void uart_putc(char c)
{
    while ((UART_FR & UART_FR_TXFF) != 0)
    {
        asm volatile("nop");
    }
    UART_DR = c;
}

void uart_puts(const char *str)
{
    while (*str)
    {
        uart_putc(*str++);
    }
}

int main(void)
{
    uart_puts("Hello from C main!\n");
    
    static int initialized_var = 42;
    static int zero_var;
    
    if (initialized_var == 42 && zero_var == 0)
    {
        uart_puts("Runtime environment OK.\n");
    }
    else
    {
        uart_puts("Runtime environment FAILED.\n");
    }

    while (1)
    {
        __asm__ volatile ("wfe");
    }
    
    return 0;
}

