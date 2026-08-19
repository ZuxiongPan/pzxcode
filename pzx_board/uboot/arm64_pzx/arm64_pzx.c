// SPDX-License-Identifier: GPL-2.0+

#include <config.h>
#include <init.h>
#include <fdtdec.h>
#include <asm/armv8/mmu.h>
#include <asm/system.h>
#include <linux/sizes.h>

static struct mm_region pzx_mem_map[] = {
	{
		/* Peripherals, MROM, SRAM (0x00000000 ~ 0x7FFFFFFF) */
		.virt = 0x00000000UL,
		.phys = 0x00000000UL,
		.size = 0x80000000UL,
		.attrs = PTE_BLOCK_MEMTYPE(MT_DEVICE_NGNRNE) |
			 PTE_BLOCK_NON_SHARE |
			 PTE_BLOCK_PXN | PTE_BLOCK_UXN
	}, {
		/* DRAM (128MB at 0x80000000) */
		.virt = 0x80000000UL,
		.phys = 0x80000000UL,
		.size = 0x08000000UL,
		.attrs = PTE_BLOCK_MEMTYPE(MT_NORMAL) |
			 PTE_BLOCK_INNER_SHARE
	}, {
		/* List terminator */
		0,
	}
};

struct mm_region *mem_map = pzx_mem_map;

int board_init(void)
{
	return 0;
}

int dram_init(void)
{
	if (fdtdec_setup_mem_size_base() != 0)
		gd->ram_size = SZ_128M;

	return 0;
}

int dram_init_banksize(void)
{
	return fdtdec_setup_memory_banksize();
}