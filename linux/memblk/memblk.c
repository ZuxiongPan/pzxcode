#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/of_reserved_mem.h>
#include "kernel/pzxktools.h"
#include "common/uk_netlink.h"

#define MEMBLK_DEVICE_NAME  "memblk"
#define MEMBLK_QUEUE_DEPTH  128
#define MEMBLK_HW_QUEUES    1

struct memblk_device {
    void __iomem *vaddr;
    resource_size_t phyaddr;
    resource_size_t memsize;
    int major;
    struct gendisk *disk;
    struct blk_mq_tag_set tag_set;
};

static struct memblk_device *memblk = NULL;

static blk_status_t memblk_queue_rq(struct blk_mq_hw_ctx *hctx,
                                    const struct blk_mq_queue_data *bd)
{
    struct request *rq = bd->rq;
    struct memblk_device *mbd = rq->q->queuedata;
    struct bio_vec bvec;
    struct req_iterator iter;
    sector_t sector = blk_rq_pos(rq);
    size_t offset = sector << SECTOR_SHIFT;
    blk_status_t ret = BLK_STS_OK;

    blk_mq_start_request(rq);

    switch(req_op(rq))
    {
    case REQ_OP_READ:
    case REQ_OP_WRITE:
        break;
    case REQ_OP_FLUSH:
        blk_mq_end_request(rq, BLK_STS_OK);
        return BLK_STS_OK;
    default:
        blk_mq_end_request(rq, BLK_STS_NOTSUPP);
        return BLK_STS_OK;
    }

    rq_for_each_segment(bvec, rq, iter)
    {
        if(unlikely(offset + bvec.bv_len > mbd->memsize))
        {
            ret = BLK_STS_IOERR;
            break;
        }

        void *addr = bvec_kmap_local(&bvec);

        if(WRITE == rq_data_dir(rq))
        {
            memcpy_toio(mbd->vaddr + offset, addr, bvec.bv_len);
        }
        else
        {
            memcpy_fromio(addr, mbd->vaddr + offset, bvec.bv_len);
        }

        offset += bvec.bv_len;
        kunmap_local(addr);
    }

    blk_mq_end_request(rq, ret);
    return BLK_STS_OK;
}

static const struct blk_mq_ops memblk_mq_ops = {
    .queue_rq = memblk_queue_rq,
};

const struct block_device_operations memdisk_fops = {
    .owner = THIS_MODULE,
};

static int memblk_probe(struct platform_device *pdev)
{
    int ret = 0;
    struct device_node *memblk_node = pdev->dev.of_node;
    struct device_node *rsvmem = NULL;
    struct resource res;
    struct queue_limits lim;

    blk_set_stacking_limits(&lim);
    lim.logical_block_size = SECTOR_SIZE;
    lim.physical_block_size = PAGE_SIZE;
    memblk = devm_kzalloc(&pdev->dev, sizeof(struct memblk_device), GFP_KERNEL);
    if(NULL == memblk)
    {
        pr_err("alloc memory block device failed\n");
        return -ENOMEM;
    }

    rsvmem = of_parse_phandle(memblk_node, "memory-region", 0);
    if(NULL == rsvmem)
    {
        pr_err("get reserved memory node for memory block device failed\n");
        return -ENODEV;
    }

    ret = of_address_to_resource(rsvmem, 0, &res);
    of_node_put(rsvmem);

    if(ret < 0)
    {
        pr_err("get reserved memory for memory device failed\n");
        return ret;
    }

    memblk->phyaddr = res.start;
    memblk->memsize = resource_size(&res);
    memblk->vaddr = devm_ioremap(&pdev->dev, memblk->phyaddr, memblk->memsize);
    if(NULL == memblk->vaddr)
    {
        pr_err("ioremap for memory block device failed\n");
        return -ENOMEM;
    }

    memblk->major = register_blkdev(0, MEMBLK_DEVICE_NAME);
    if(memblk->major < 0)
    {
        pr_err("register %s block device failed\n", MEMBLK_DEVICE_NAME);
        return -ENODEV;
    }

    memblk->tag_set.ops = &memblk_mq_ops;
    memblk->tag_set.nr_hw_queues = MEMBLK_HW_QUEUES;
    memblk->tag_set.queue_depth = MEMBLK_QUEUE_DEPTH;
    memblk->tag_set.numa_node = NUMA_NO_NODE;

    ret = blk_mq_alloc_tag_set(&memblk->tag_set);
    if(ret < 0)
    {
        pr_err("alloc tag set for %s failed\n", MEMBLK_DEVICE_NAME);
        unregister_blkdev(memblk->major, MEMBLK_DEVICE_NAME);
        return ret;
    }

    memblk->disk = blk_mq_alloc_disk(&memblk->tag_set, &lim, memblk);
    if(IS_ERR(memblk->disk))
    {
        pr_err("failed to allocate disk for %s\n", MEMBLK_DEVICE_NAME);
        ret = PTR_ERR(memblk->disk);
        blk_mq_free_tag_set(&memblk->tag_set);
        unregister_blkdev(memblk->major, MEMBLK_DEVICE_NAME);
        return ret;
    }

    memblk->disk->major = memblk->major;
    memblk->disk->first_minor = 0;
    memblk->disk->minors = 1;
    memblk->disk->fops = &memdisk_fops;
    memblk->disk->private_data = memblk;
    snprintf(memblk->disk->disk_name, DISK_NAME_LEN, MEMBLK_DEVICE_NAME);
    
    set_capacity(memblk->disk, memblk->memsize >> SECTOR_SHIFT);

    ret = add_disk(memblk->disk);
    if(ret < 0)
    {
        pr_err("add %s disk failed\n", MEMBLK_DEVICE_NAME);
        put_disk(memblk->disk);
        blk_mq_free_tag_set(&memblk->tag_set);
        unregister_blkdev(memblk->major, MEMBLK_DEVICE_NAME);
    }

    pr_info("memblk init ret = %d, block device start address 0x%llx\n", ret, (unsigned long long)memblk->vaddr);
    genl_async_send(USER_MEMBLK_MODNAME, ACT_ADD, MEMBLK_DEVICE_NAME, sizeof(MEMBLK_DEVICE_NAME));

    return ret;
}

static void memblk_remove(struct platform_device *pdev)
{
    genl_async_send(USER_MEMBLK_MODNAME, ACT_REMOVE, MEMBLK_DEVICE_NAME, sizeof(MEMBLK_DEVICE_NAME));
    del_gendisk(memblk->disk);
    put_disk(memblk->disk);
    blk_mq_free_tag_set(&memblk->tag_set);
    unregister_blkdev(memblk->major, MEMBLK_DEVICE_NAME);
    pr_info("memory block disk released\n");

    return ;
}

static const struct of_device_id memblk_ids[] = {
    { .compatible = "pzx,memblk" },
    { }
};

static struct platform_driver memblk_drv = {
    .probe = memblk_probe,
    .remove = memblk_remove,
    .driver = {
        .name = "memblk",
        .of_match_table = memblk_ids,
    },
};

module_platform_driver(memblk_drv);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("pzx, pzxiong9865@gmail.com");
MODULE_DESCRIPTION("a memory block driver");
