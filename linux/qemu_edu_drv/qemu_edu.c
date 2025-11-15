#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/io-mapping.h>
#include <linux/interrupt.h>
#include <linux/moduleparam.h>
#include <linux/stat.h>
#include <linux/types.h>
#include <linux/completion.h>
#include <linux/dma-mapping.h>
#include <linux/ioctl.h>
#include <linux/delay.h>
#include "qemu_edu.h"

struct edu_device {
    struct pci_dev *pdev;
    void __iomem *mmio_base;
    unsigned int irq;

    struct cdev cdev;
    dev_t devno;
    struct class *class;
    struct device *device;
    struct completion fact;
    struct completion dma;
};

static irqreturn_t edu_isr(int irq, void *dev)
{
    struct edu_device *edu_dev = dev;
    u32 status = ioread32(edu_dev->mmio_base + EDU_IRQSTATUS_REG);

    if(!status)
        return IRQ_NONE;
    
    iowrite32(status, edu_dev->mmio_base + EDU_IRQACK_REG);

    if(status & IRQSTATUS_DMA)
    {
        pr_info("edu device DMA transfer irq status 0x%x\n", status);
        complete(&edu_dev->dma);
    }

    if(status & IRQSTATUS_FACT)
    {
        u32 result = ioread32(edu_dev->mmio_base + EDU_FACTORIAL_REG);
        pr_info("edu device calculate factorial result %u\n", result);
        complete(&edu_dev->fact);
    }

    return IRQ_HANDLED;
}

static void edu_request_factorial(struct edu_device *edu_dev, unsigned int num)
{
    u32 status;

    do {
        status = ioread32(edu_dev->mmio_base + EDU_STATUS_REG);
    } while(status & STATUS_BUSY);

    reinit_completion(&edu_dev->fact);
    iowrite32(num, edu_dev->mmio_base + EDU_FACTORIAL_REG);
    iowrite32(IRQSTATUS_FACT, edu_dev->mmio_base + EDU_IRQRAISE_REG);

    pr_info("request factorial of %u\n", num);
    return ;
}

static int edu_do_dma(struct edu_device *edu_dev, const struct edu_dma_req *req)
{
    if(req->len > DMA_MAXBYTES)
    {
        pr_err("dma request size is %u, max %u\n", req->len, DMA_MAXBYTES);
        return -EINVAL;
    }

    dma_addr_t dma_dev_handle;
    unsigned int cmd = DMA_START_FLAG;
    void *dma_ram_buf = dma_alloc_coherent(&edu_dev->pdev->dev, req->len,
            &dma_dev_handle, GFP_KERNEL | GFP_DMA32);
    if(NULL == dma_ram_buf)
    {
        pr_err("edu device request dma buffer failed\n");
        return -ENOMEM;
    }
    pr_info("dma alloc return handle 0x%llx, buf 0x%lx length %u\n",
        dma_dev_handle, (unsigned long)dma_ram_buf, req->len);

    if(req->dir == DMA_RAM2EDU)
    {
        if(copy_from_user(dma_ram_buf, req->buf, req->len))
        {
            pr_err("get data from user failed\n");
            dma_free_coherent(&edu_dev->pdev->dev, req->len, dma_ram_buf, dma_dev_handle);
            return -EFAULT;
        }
    }

    if(dma_dev_handle & ~DMA_BIT_MASK(DMA_MASK_BITS))
    {
        pr_err("dma device address is 0x%llx, invalid\n", dma_dev_handle);
        dma_free_coherent(&edu_dev->pdev->dev, req->len, dma_ram_buf, dma_dev_handle);
        return -EIO;
    }

    if(req->dir == DMA_RAM2EDU)
    {
        iowrite32(dma_dev_handle, edu_dev->mmio_base + EDU_DMA_SRCADDR_REG);
        iowrite32((u32)DMA_EDUBUF_OFFSET, edu_dev->mmio_base + EDU_DMA_DSTADDR_REG);
    }
    else
    {
        iowrite32((u32)DMA_EDUBUF_OFFSET, edu_dev->mmio_base + EDU_DMA_SRCADDR_REG);
        iowrite32(dma_dev_handle, edu_dev->mmio_base + EDU_DMA_DSTADDR_REG);
        cmd |= DMA_DIRECTION_FLAG;
    }

    iowrite32((u32)req->len, edu_dev->mmio_base + EDU_DMA_COUNT_REG);
    cmd |= DMA_RAISEIRQ_FLAG;
    iowrite32(cmd, edu_dev->mmio_base + EDU_DMA_CMD_REG);

    reinit_completion(&edu_dev->dma);

    if(!(wait_for_completion_timeout(&edu_dev->dma, msecs_to_jiffies(5000))))
    {
        pr_err("edu dma op timeout\n");
        dma_free_coherent(&edu_dev->pdev->dev, req->len, dma_ram_buf, dma_dev_handle);
        return -ETIMEDOUT;
    }

    if(req->dir == DMA_EDU2RAM)
    {
        if(copy_to_user(req->buf, dma_ram_buf, req->len))
        {
            pr_err("copy to user failed\n");
            dma_free_coherent(&edu_dev->pdev->dev, req->len, dma_ram_buf, dma_dev_handle);
            return -EFAULT;
        }
    }

    dma_free_coherent(&edu_dev->pdev->dev, req->len, dma_ram_buf, dma_dev_handle);
    pr_info("edu device dma op success, direction %s, length %u\n",
        req->dir ? "ram->edu" : "edu->ram", req->len);

    return 0;
}

static int edu_open(struct inode *pnode, struct file *filp)
{
    struct edu_device *edu_dev = container_of(pnode->i_cdev, struct edu_device, cdev);
    filp->private_data = edu_dev;

    return 0;
}

static long edu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int ret = 0;
    u32 data = 0;
    struct edu_device *edu_dev = filp->private_data;
    struct edu_dma_req req;
    memset(&req, 0, sizeof(req));

    if(_IOC_TYPE(cmd) != EDU_IOC_MAGIC)
    {
        pr_err("invalid ioctl cmd 0x%x\n", cmd);
        return -EBADRQC;
    }

    switch(cmd)
    {
        case EDU_IOC_VER:
            data = ioread32(edu_dev->mmio_base + EDU_VERSION_REG);
            pr_info("edu device version is 0x%x\n", data);
            break;
        case EDU_IOC_FACT:
            if(copy_from_user(&data, (void __user *)arg, sizeof(unsigned int)))
            {
                pr_err("get factorial data failed\n");
                return -EFAULT;
            }
            edu_request_factorial(edu_dev, data);
            if(!wait_for_completion_timeout(&edu_dev->fact, msecs_to_jiffies(100)))
            {
                pr_err("waiting for factorial IRQ timeout\n");
                return -ETIMEDOUT;
            }
            break;
        case EDU_IOC_DMA:
            if(copy_from_user(&req, (void __user *)arg, sizeof(struct edu_dma_req)))
            {
                pr_err("get dma request failed\n");
                return -EFAULT;
            }
            if(req.dir > DMA_RAM2EDU || req.len <=0 || req.len > DMA_MAXBYTES || !req.buf)
            {
                pr_err("dma arguments are invalid\n");
                return -EINVAL;
            }
            ret = edu_do_dma(edu_dev, &req);
            break;
        default:
            pr_err("invalid ioctl cmd 0x%x\n", cmd);
            return -EBADRQC;
    }

    return ret;
}

static const struct file_operations edu_fops = {
    .owner = THIS_MODULE,
    .open = edu_open,
    .unlocked_ioctl = edu_ioctl,
};

static inline void edu_device_liveness_check(const struct edu_device *edu_dev)
{
    u32 val = 0x55aa55aa;
    iowrite32(val, edu_dev->mmio_base + EDU_LIVENESS_REG);
    mdelay(5);
    val = ioread32(edu_dev->mmio_base + EDU_LIVENESS_REG);
    pr_info("liveness check, read out %x, need 0xaa55aa55\n", val);

    return ;
}

static int edu_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    pr_info("start probe device 0x%04x:0x%04x\n", id->vendor, id->device);

    int ret = 0;
    struct edu_device *edu_dev = devm_kzalloc(&pdev->dev, sizeof(struct edu_device), GFP_KERNEL);
    if(NULL == edu_dev)
    {
        pr_err("cannot allocate memory for edu device\n");
        return -ENOMEM;
    }

    edu_dev->pdev = pdev;
    pci_set_drvdata(pdev, edu_dev);

    ret = pci_enable_device(pdev);
    if(ret)
    {
        pr_err("cannot enable pci device, ret %d\n", ret);
        return ret;
    }

    ret = dma_set_mask(&pdev->dev, DMA_BIT_MASK(DMA_MASK_BITS)) || 
        dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(DMA_MASK_BITS));
    if(ret)
    {
        pr_err("failed to set dma mask for edu device\n");
        goto disable_dev;
    }

    ret = pci_request_regions(pdev, drv_name);
    if(ret)
    {
        pr_err("reserve io memory resource failed\n");
        goto disable_dev;
    }

    edu_dev->mmio_base = pci_iomap(pdev, EDU_BAR, 0);
    if(NULL == edu_dev->mmio_base)
    {
        pr_err("iomap bar failed\n");
        ret = -EIO;
        goto release_regions;
    }

    edu_dev->irq = pdev->irq;
    ret = request_irq(edu_dev->irq, edu_isr, IRQF_SHARED, drv_name, edu_dev);
    if(ret)
    {
        pr_err("request interrupt failed\n");
        goto unmap_mmio;
    }

    init_completion(&edu_dev->fact);
    init_completion(&edu_dev->dma);

    edu_device_liveness_check(edu_dev);

    ret = alloc_chrdev_region(&edu_dev->devno, 0, 1, drv_name);
    if(ret)
    {
        pr_err("failed to acquire cdev number\n");
        goto release_irq;
    }

    cdev_init(&edu_dev->cdev, &edu_fops);
    edu_dev->cdev.owner = THIS_MODULE;
    
    ret = cdev_add(&edu_dev->cdev, edu_dev->devno, 1);
    if(ret)
    {
        pr_err("add edu character device failed\n");
        goto unregister_region;
    }

    edu_dev->class = class_create(drv_name);
    if(IS_ERR(edu_dev->class))
    {
        ret = PTR_ERR(edu_dev->class);
        pr_err("create edu device class failed\n");
        goto delete_chrdev;
    }

    edu_dev->device = device_create(edu_dev->class, NULL, edu_dev->devno, NULL, drv_name);
    if(IS_ERR(edu_dev->device))
    {
        ret = PTR_ERR(edu_dev->device);
        pr_err("create edu device failed\n");
        goto destroy_class;
    }

    pr_info("edu device create success\n");
    return ret;

destroy_class:
    class_destroy(edu_dev->class);
delete_chrdev:
    cdev_del(&edu_dev->cdev);
unregister_region:
    unregister_chrdev_region(edu_dev->devno, 1);
release_irq:
    free_irq(edu_dev->irq, edu_dev);
unmap_mmio:
    pci_iounmap(pdev, edu_dev->mmio_base);
release_regions:
    pci_release_regions(pdev);
disable_dev:
    pci_disable_device(pdev);

    return ret;
}

static void edu_remove(struct pci_dev *pdev)
{
    struct edu_device *edu_dev = pci_get_drvdata(pdev);

    device_destroy(edu_dev->class, edu_dev->devno);
    class_destroy(edu_dev->class);
    cdev_del(&edu_dev->cdev);
    unregister_chrdev_region(edu_dev->devno, 1);
    free_irq(edu_dev->irq, edu_dev);
    pci_iounmap(pdev, edu_dev->mmio_base);
    pci_release_regions(pdev);
    pci_disable_device(pdev);

    pr_info("edu device is removed\n");
    return;
}

static const struct pci_device_id edu_id[] = {
    { PCI_DEVICE(EDU_VENDID, EDU_DEVID), },
    { 0, },
};
MODULE_DEVICE_TABLE(pci, edu_id);

static struct pci_driver edu_driver = {
    .name = drv_name,
    .id_table = edu_id,
    .probe = edu_probe,
    .remove = edu_remove,
};

module_pci_driver(edu_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("a simple driver for qemu edu");
