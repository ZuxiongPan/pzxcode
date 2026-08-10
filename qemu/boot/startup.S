
.global _start
.section ".text.startup"

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

    // 4. copy data (MROM -> SRAM2)
    ldr x0, =__data_load_start__
    ldr x1, =__data_start__
    ldr x2, =__data_end__
data_copy_loop:
    cmp x1, x2
    b.ge data_copy_done
    ldr x3, [x0], #8
    str x3, [x1], #8
    b data_copy_loop
data_copy_done:

    // 5. run main function
    // when return from main
    // register x0 is the entry address of sd code
    bl main

    // 6. memory barriers for refresh
    ic iallu    // invalidate all instruction caches
    dsb nsh     // data synchronization barrier
    isb         // instruction synchronization barrier

    // 7. run sd code
    br x0

halt:
    wfe
    b halt

