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
#define EDU_IRQRAISE_REG 0x60 // WO
#define EDU_IRQACK_REG 0x64 // WO
#define EDU_DMA_SRCADDR_REG 0x80 //RW
#define EDU_DMA_DSTADDR_REG 0x88 // RW
#define EDU_DMA_COUNT_REG 0x90 // RW
#define EDU_DMA_CMD_REG 0x98 // RW

#define STATUS_BUSY 0x01
#define IRQSTATUS_FACT 0x80
#define IRQSTATUS_DMA 0x100
#define DMA_START_FLAG 0x01
#define DMA_DIRECTION_FLAG 0x02
#define DMA_RAISEIRQ_FLAG 0x04
#define DMA_EDUBUF_OFFSET 0x40000
#define DMA_EDU2RAM 0
#define DMA_RAM2EDU 1
// PCI do not support dma mask below 32bit
#define DMA_MASK_BITS 32
#define DMA_MAXBYTES 4096

struct edu_dma_req {
    unsigned char dir;
    unsigned int len;
    void __user *buf;
};

#define EDU_IOC_MAGIC 'e'
#define EDU_IOC_VER _IO(EDU_IOC_MAGIC, 1)
#define EDU_IOC_FACT _IOR(EDU_IOC_MAGIC, 2, unsigned int)
#define EDU_IOC_DMA _IOWR(EDU_IOC_MAGIC, 3, struct edu_dma_req)

#endif