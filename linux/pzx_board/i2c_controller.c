#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/completion.h>

struct pzx_i2c {
    void __iomem *base;
    int irq;
    struct i2c_adapter adap;
    struct completion xfer_done;
};

// register definitions
#define PZX_I2C_CR      0x00
#define PZX_I2C_SR      0x04
#define PZX_I2C_ADDR    0x08
#define PZX_I2C_DR      0x0c

#define CR_EN (1u << 0)
#define CR_IEN (1u << 1)
#define CR_START (1u << 2)
#define CR_STOP (1u << 3)
#define CR_DIR (1u << 4) // 0-write 1-read
#define CR_NACK (1u << 5)

#define SR_BUSY (1u << 0)
#define SR_RXAK (1u << 1)
#define SR_IF (1u << 2)

static irqreturn_t pzx_i2c_isr(int irq, void *dev_id)
{
    struct pzx_i2c *i2c = dev_id;
    u32 sr;
    sr = readl(i2c->base + PZX_I2C_SR);
    if (!(sr & SR_IF))
    {
        return IRQ_NONE;
    }
    writel(SR_IF, i2c->base + PZX_I2C_SR);
    complete(&i2c->xfer_done);
    return IRQ_HANDLED;
}

static int pzx_i2c_xfer_msg(struct pzx_i2c *i2c, struct i2c_msg *msg)
{
    bool is_read = (msg->flags & I2C_M_RD);
    u32 cr = CR_EN | CR_IEN;
    u32 sr;
    int i;

    reinit_completion(&i2c->xfer_done);

    // 1. set slave address
    writel(msg->addr & 0x7f, i2c->base + PZX_I2C_ADDR);

    // 2. set read/write direction
    if (is_read)
        cr |= CR_DIR;
    else
        cr &= ~CR_DIR;

    // 3. send start signal
    cr |= CR_START;
    writel(cr, i2c->base + PZX_I2C_CR);

    // 4. wait for hardware interrupt response
    if (!wait_for_completion_timeout(&i2c->xfer_done, msecs_to_jiffies(100))) {
        return -ETIMEDOUT;
    }

    // 5. check if device responded (SR_RXAK set means NACK)
    sr = readl(i2c->base + PZX_I2C_SR);
    if (sr & SR_RXAK) {
        // no response, send stop and return -ENXIO
        writel(CR_EN | CR_STOP, i2c->base + PZX_I2C_CR);
        return -ENXIO;
    }

    // 6. data transfer stage
    if (is_read) {
        for (i = 0; i < msg->len; i++) {
            reinit_completion(&i2c->xfer_done);
            msg->buf[i] = readl(i2c->base + PZX_I2C_DR);
        }
    } else {
        for (i = 0; i < msg->len; i++) {
            reinit_completion(&i2c->xfer_done);
            writel(msg->buf[i], i2c->base + PZX_I2C_DR);
            if (!wait_for_completion_timeout(&i2c->xfer_done, msecs_to_jiffies(100))) {
                return -ETIMEDOUT;
            }
            sr = readl(i2c->base + PZX_I2C_SR);
            if (sr & SR_RXAK) {
                writel(CR_EN | CR_STOP, i2c->base + PZX_I2C_CR);
                return -ENXIO;
            }
        }
    }

    // 7. send stop signal to end transfer
    reinit_completion(&i2c->xfer_done);
    writel(CR_EN | CR_STOP, i2c->base + PZX_I2C_CR);
    wait_for_completion_timeout(&i2c->xfer_done, msecs_to_jiffies(100));

    return 0;
}

static int pzx_i2c_xfer(struct i2c_adapter *adap, struct i2c_msg *msgs, int num)
{
    struct pzx_i2c *i2c = i2c_get_adapdata(adap);
    int i, ret;

    for (i = 0; i < num; i++) {
        ret = pzx_i2c_xfer_msg(i2c, &msgs[i]);
        if (ret < 0)
            return ret;
    }

    return num;
}

static u32 pzx_i2c_func(struct i2c_adapter *adap)
{
    return I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL;
}

static const struct i2c_algorithm pzx_i2c_algo = {
    .master_xfer = pzx_i2c_xfer,
    .functionality = pzx_i2c_func,
};

static int pzx_i2c_probe(struct platform_device *pdev)
{
    struct pzx_i2c *i2c;
    struct resource *res;
    int ret;

    i2c = devm_kzalloc(&pdev->dev, sizeof(*i2c), GFP_KERNEL);
    if (!i2c) return -ENOMEM;

    res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
    i2c->base = devm_ioremap_resource(&pdev->dev, res);
    if (IS_ERR(i2c->base)) return PTR_ERR(i2c->base);

    i2c->irq = platform_get_irq(pdev, 0);
    if (i2c->irq < 0) return i2c->irq;

    init_completion(&i2c->xfer_done);

    ret = devm_request_irq(&pdev->dev, i2c->irq, pzx_i2c_isr, 0, pdev->name, i2c);
    if (ret) return ret;

    snprintf(i2c->adap.name, sizeof(i2c->adap.name), "pzx i2c [0x%p]", i2c->base);
    i2c->adap.owner = THIS_MODULE;
    i2c->adap.algo = &pzx_i2c_algo;
    i2c->adap.dev.parent = &pdev->dev;
    i2c_set_adapdata(&i2c->adap, i2c);

    return i2c_add_adapter(&i2c->adap);
}

static void pzx_i2c_remove(struct platform_device *pdev)
{
    struct pzx_i2c *i2c = platform_get_drvdata(pdev);
    i2c_del_adapter(&i2c->adap);
    return ;
}

static const struct of_device_id pzx_i2c_match[] = {
    { .compatible = "pzx,pzx-i2c" },
    { },
};
MODULE_DEVICE_TABLE(of, pzx_i2c_match);

static struct platform_driver pzx_i2c_driver = {
    .probe = pzx_i2c_probe,
    .remove = pzx_i2c_remove,
    .driver = {
        .name = "pzx-i2c",
        .of_match_table = pzx_i2c_match,
    },
};
module_platform_driver(pzx_i2c_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("pzx custom i2c bus driver");
