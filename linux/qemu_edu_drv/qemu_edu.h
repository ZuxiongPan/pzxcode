#ifndef __QEMU_EDU__
#define __QEMU_EDU__

#define drv_name "qemu_edu"
#define EDU_DEVID 0x11e8
#define EDU_VENDID 0x1234

#define EDU_BAR 0x0

#define EDU_VERSION_REG 0x0 //RO
#define EDU_LIVENESS_REG 0x04 // RW
#define EDU_FACTORIAL_REG 0x08 // RW
#define EDU_STATUS_REG 0x20 // RW
#define EDU_IRQSTATUS_REG 0x24 // RO
#define EDU_INTRAISE_REG 0x60 // WO
#define EDU_INTACK_REG 0x64 // WO
#define EDU_DMA_SRCADDR_REG 0x80 //RW
#define EDU_DMA_DSTADDR_REG 0x88 // RW
#define EDU_DMA_COUNT_REG 0x90 // RW
#define EDU_DMACMD_REG 0x98 // RW

#define STATUS_BUSY 0x01
#define STATUS_INTEN 0x80
#define IRQSTATUS_RAISE_ENDDMA 0x100
#define DMA_DIRECTION_FLAG 0x02

enum edu_dma_direction {
    DMA_EDU2RAM = 0,
    DMA_RAM2EDU,
};

#endif