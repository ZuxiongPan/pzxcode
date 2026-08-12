
.global _start
.section ".text.loader"

_start:
    // 1. shield interrupts
    msr daifset, #0xf

    // 2. set stack pointer(sram top)
    ldr x0, =0x00200000
    mov sp, x0

    // 3. bss zero
    ldr x0, =__bss_start__
    ldr x1, =__bss_end__
bss_loop:
    cmp x0, x1
    b.ge bss_done
    str xzr, [x0], #8
    b bss_loop
bss_done:

    // 4. run main function
    bl main

    // 5. memory barriers for refresh
    ic iallu    // invalidate all instruction caches
    dsb nsh     // data synchronization barrier
    isb         // instruction synchronization barrier

    // 6. run uboot
    br x0

halt:
    wfe
    b halt

