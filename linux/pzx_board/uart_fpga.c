#include <linux/module.h>
#include <linux/of.h>
#include <linux/serdev.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/workqueue.h>

#define BUFSIZE 32
#define BAUDRATE 115200

enum {
    CMD_INVALID = 0,
    CMD_VERSION,
    CMD_TIME,
};

struct fpga_cmd {
    const char *name;
    int total_len;
    u8 content[BUFSIZE];
};

enum recv_stat {
    STAT_WAIT_SOF = 0,
    STAT_WAIT_LEN,
    STAT_WAIT_PALOAD,
    STAT_WAIT_EOF,
};

struct uart_fpga {
    struct serdev_device *serdev;
    struct mutex mutex;

    enum recv_stat stat;
    u8 rx_len;
    u8 rx_buf[BUFSIZE];
    u8 rx_cnt;

    struct delayed_work work;
};

static struct uart_fpga *g_fpga = NULL;

static const struct fpga_cmd fpga_cmd_list[] = {
    [CMD_VERSION] = { 
        .name = "VERSION", 
        .total_len = 10, 
        .content = { 0x02, 0x07, 'V', 'E', 'R', 'S', 'I', 'O', 'N', 0x03 }
    },
    [CMD_TIME] = { 
        .name = "TIME", 
        .total_len = 7, 
        .content = { 0x02, 0x04, 'T', 'I', 'M', 'E', 0x03 }
    },
};

static size_t uart_fpga_receive(struct serdev_device *serdev, const u8 *buf, size_t len)
{
    struct uart_fpga *fpga = serdev_device_get_drvdata(serdev);
    size_t i = 0;
    u8 ch = 0;

    while(i < len)
    {
        ch = buf[i];

        switch(fpga->stat)
        {
            case STAT_WAIT_SOF:
                if (ch == 0x02)
                {
                    fpga->stat = STAT_WAIT_LEN;
                }
                break;
            case STAT_WAIT_LEN:
                fpga->rx_len = ch;
                fpga->rx_cnt = 0;
                if (fpga->rx_len > 0 && fpga->rx_len < sizeof(fpga->rx_buf))
                {
                    fpga->stat = STAT_WAIT_PALOAD;
                }
                else
                {
                    fpga->stat = STAT_WAIT_SOF;
                }
                break;
            case STAT_WAIT_PALOAD:
                fpga->rx_buf[fpga->rx_cnt++] = ch;
                if (fpga->rx_cnt >= fpga->rx_len)
                {
                    fpga->stat = STAT_WAIT_EOF;
                }
                break;
            case STAT_WAIT_EOF:
                if (ch == 0x03)
                {
                    fpga->rx_buf[fpga->rx_len] = '\0';
                    pr_info("receive from fpga [%s]\n", fpga->rx_buf);
                }
                fpga->stat = STAT_WAIT_SOF;
                break;
        }
        i++;
    }

    return len;
}

static void uart_fpga_write_wakeup(struct serdev_device *serdev)
{
    serdev_device_write_wakeup(serdev);
}

static const struct serdev_device_ops uart_fpga_ops = {
    .receive_buf = uart_fpga_receive,
    .write_wakeup = uart_fpga_write_wakeup,
};

static inline int uart_fpga_send_cmd(struct uart_fpga *fpga, int cmd)
{
    int ret = 0;
    
    mutex_lock(&fpga->mutex);
    ret = serdev_device_write(fpga->serdev, fpga_cmd_list[cmd].content,
        fpga_cmd_list[cmd].total_len, msecs_to_jiffies(1000));
    mutex_unlock(&fpga->mutex);
    pr_info("send cmd %s, ret = %d\n", fpga_cmd_list[cmd].name, ret);

    return ret;
}

static void uart_fpga_init_work(struct work_struct *work)
{
    struct uart_fpga *fpga = container_of(to_delayed_work(work), struct uart_fpga, work);
    pr_info("sending version and time commands\n");
    uart_fpga_send_cmd(fpga, CMD_VERSION);
    msleep(50);
    uart_fpga_send_cmd(fpga, CMD_TIME);
}

static int uart_fpga_probe(struct serdev_device *serdev)
{
    int ret = 0;

    g_fpga = devm_kzalloc(&serdev->dev, sizeof(struct uart_fpga), GFP_KERNEL);
    if (NULL == g_fpga)
    {
        return -ENOMEM;
    }

    g_fpga->serdev = serdev;
    mutex_init(&g_fpga->mutex);
    serdev_device_set_drvdata(serdev, g_fpga);
    serdev->ops = &uart_fpga_ops;

    ret = serdev_device_open(serdev);
    if (ret < 0)
    {
        pr_err("uart_fpga_probe: serdev_device_open failed, ret = %d\n", ret);
        return ret;
    }

    serdev_device_set_baudrate(serdev, BAUDRATE);
    serdev_device_set_flow_control(serdev, false);

    INIT_DELAYED_WORK(&g_fpga->work, uart_fpga_init_work);
    schedule_delayed_work(&g_fpga->work, msecs_to_jiffies(500));
    pr_info("bind serdev and serial success\n");
    return 0;
}

static void uart_fpga_remove(struct serdev_device *serdev)
{
    if (NULL != g_fpga)
    {
        cancel_delayed_work(&g_fpga->work);
        g_fpga = NULL;
    }
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
MODULE_DESCRIPTION("a custom protocol fpga driver based on serdev");
