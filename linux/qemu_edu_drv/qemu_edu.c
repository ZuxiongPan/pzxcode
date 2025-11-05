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
#include "qemu_edu.h"

unsigned char calnum = 10;
module_param(calnum, byte, 0644);

struct edu_device {
    struct pci_dev *pdev;
    void __iomem *mmio_base;
    unsigned int irq;

    struct cdev cdev;
    dev_t devno;
    struct class *class;
    struct device *device;
    struct completion done;
};

static irqreturn_t edu_isr(int irq, void *dev)
{
    struct edu_device *edu_dev = dev;
    u32 status = ioread32(edu_dev->mmio_base + EDU_INTRAISE_REG);

    if(!status)
        return IRQ_NONE;
    
    iowrite32(status, edu_dev->mmio_base + EDU_INTACK_REG);

    u32 result = ioread32(edu_dev->mmio_base + EDU_FACTORIAL_REG);
    pr_info("edu calculate factorial result is %u\n", result);

    complete(&edu_dev->done);
    return IRQ_HANDLED;
}

static void edu_request_factorial(struct edu_device *edu_dev, unsigned int num)
{
    u32 status;

    do {
        status = ioread32(edu_dev->mmio_base + EDU_STATUS_REG);
    } while(status & STATUS_BUSY);

    iowrite32(num, edu_dev->mmio_base + EDU_FACTORIAL_REG);
    iowrite32(STATUS_INTEN, edu_dev->mmio_base + EDU_STATUS_REG);

    reinit_completion(&edu_dev->done);
    pr_info("request factorial of %u\n", num);
    return ;
}

static int edu_open(struct inode *pnode, struct file *filp)
{
    struct edu_device *edu_dev = container_of(pnode->i_cdev, struct edu_device, cdev);
    filp->private_data = edu_dev;

    return 0;
}

static ssize_t edu_write(struct file *filp, const char __user *buf, size_t cnt, loff_t *ppos)
{
    char kbuf[8];
    unsigned int val = 0;
    struct edu_device *edu_dev = filp->private_data;

    if(cnt > sizeof(kbuf))
    {
        return -EINVAL;
    }

    if(copy_from_user(kbuf, buf, cnt))
    {
        return -EFAULT;
    }

    kstrtouint(kbuf, 10, &val);
    if(val > 12)
    {
        pr_notice("unsigned int factorial max value is 12!\n");
        val = 12;
    }

    edu_request_factorial(edu_dev, val);
    if(!wait_for_completion_timeout(&edu_dev->done, msecs_to_jiffies(10)))
    {
        pr_err("waiting for factorial IRQ timeout\n");
        return -ETIMEDOUT;
    }

    return cnt;
}

static const struct file_operations edu_fops = {
    .owner = THIS_MODULE,
    .open = edu_open,
    .write = edu_write,
};

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

    init_completion(&edu_dev->done);

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
