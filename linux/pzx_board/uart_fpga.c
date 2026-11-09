#include <linux/module.h>
#include <linux/of.h>
#include <linux/serdev.h>
#include <linux/mutex.h>
#include <linux/delay.h>

struct uart_fpga {
    struct serdev_device *serdev;
    struct mutex mutex;
};

static size_t uart_fpga_receive(struct serdev_device *uart, const u8 *buf, size_t len)
{
    pr_info("uart_fpga_receive: %s\n", buf);
    return len;
}

static const struct serdev_device_ops uart_fpga_ops = {
    .receive_buf = uart_fpga_receive,
};

// static ssize_t uart_fpga_send(struct uart_fpga *uart, const u8 *data, size_t len)
// {
//     ssize_t ret = 0;
//     mutex_lock(&uart->mutex);
//     ret = serdev_device_write(uart->serdev, data, len, msecs_to_jiffies(300));
//     mutex_unlock(&uart->mutex);

//     return ret;
// }

static int uart_fpga_probe(struct serdev_device *serdev)
{
    struct uart_fpga *uart = NULL;
    u32 baudrate = 115200;
    int ret = 0;

    uart = devm_kzalloc(&serdev->dev, sizeof(struct uart_fpga), GFP_KERNEL);
    if (NULL == uart)
    {
        return -ENOMEM;
    }

    uart->serdev = serdev;
    mutex_init(&uart->mutex);
    serdev_device_set_drvdata(serdev, uart);
    serdev->ops = &uart_fpga_ops;

    ret = serdev_device_open(serdev);
    if (ret < 0)
    {
        pr_err("uart_fpga_probe: serdev_device_open failed, ret = %d\n", ret);
        return ret;
    }

    serdev_device_set_baudrate(serdev, baudrate);
    serdev_device_set_flow_control(serdev, false);

    pr_info("bind serdev and serial success\n");
    return 0;
}

static void uart_fpga_remove(struct serdev_device *serdev)
{
    serdev_device_close(serdev);
    return ;
}

static const struct of_device_id uart_fpga_of_match[] = {
    { .compatible = "pzx,uart-fpga" },
    {}
};
MODULE_DEVICE_TABLE(of, uart_fpga_of_match);

static struct serdev_device_driver uart_fpga_driver = {
    .driver = {
        .name = "uart_fpga",
        .of_match_table = uart_fpga_of_match,
    },
    .probe = uart_fpga_probe,
    .remove = uart_fpga_remove,
};
module_serdev_device_driver(uart_fpga_driver);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("a fpga driver based on serdev");
