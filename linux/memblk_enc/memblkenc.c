#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/of_reserved_mem.h>

#define MEMBLKENC_DEVICE_NAME "memblkenc"

struct memblkenc_device {
    void __iomem *vaddr;
    resource_size_t phyaddr;
    resource_size_t memsize;
    int major;
    struct gendisk *disk;
};

static struct memblkenc_device *memblkenc = NULL;

static void memblkenc_submit_bio(struct bio *bio)
{
    struct memblkenc_device *mbed = bio->bi_bdev->bd_disk->private_data;
    struct bio_vec bvec;
    struct bvec_iter biter;
    sector_t sector = bio->bi_iter.bi_sector;
    size_t offset = sector << SECTOR_SHIFT;

    bio_for_each_segment(bvec, bio, biter)
    {
        void *addr = kmap_atomic(bvec.bv_page) + bvec.bv_offset;

        if(unlikely(offset + bvec.bv_len > mbed->memsize))
        {
            kunmap_atomic(addr);
            bio_io_error(bio);
            return ;
        }

        if(WRITE == bio_data_dir(bio))
        {
            memcpy(mbed->vaddr + offset, addr, bvec.bv_len);
        }
        else
        {
            memcpy(addr, mbed->vaddr + offset, bvec.bv_len);
        }

        offset += bvec.bv_len;
        kunmap_atomic(addr);
    }

    bio_endio(bio);
    return ;
}

const struct block_device_operations memdiskenc_fops = {
    .owner = THIS_MODULE,
    .submit_bio = memblkenc_submit_bio,
};

static int memblkenc_probe(struct platform_device *pdev)
{
    int ret = 0;
    struct device_node *memblk_node = pdev->dev.of_node;
    struct device_node *rsvmem = NULL;
    struct resource res;
    struct queue_limits lim;

    blk_set_stacking_limits(&lim);
    lim.logical_block_size = SECTOR_SIZE;
    lim.physical_block_size = PAGE_SIZE;
    lim.features |= BLK_FEAT_SYNCHRONOUS;
    memblkenc = devm_kzalloc(&pdev->dev, sizeof(struct memblkenc_device), GFP_KERNEL);
    if(NULL == memblkenc)
    {
        pr_err("alloc memory block encry device failed\n");
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

    memblkenc->phyaddr = res.start;
    memblkenc->memsize = resource_size(&res);
    memblkenc->vaddr = devm_ioremap(&pdev->dev, memblkenc->phyaddr, memblkenc->memsize);
    if(NULL == memblkenc->vaddr)
    {
        pr_err("ioremap for memory block device failed\n");
        return -ENOMEM;
    }

    memblkenc->major = register_blkdev(0, MEMBLKENC_DEVICE_NAME);
    if(memblkenc->major < 0)
    {
        pr_err("register %s block device failed\n", MEMBLKENC_DEVICE_NAME);
        return -ENODEV;
    }

    memblkenc->disk = blk_alloc_disk(&lim, NUMA_NO_NODE);
    if(IS_ERR(memblkenc->disk))
    {
        pr_err("failed to allocate disk for %s\n", MEMBLKENC_DEVICE_NAME);
        unregister_blkdev(memblkenc->major, MEMBLKENC_DEVICE_NAME);
        return PTR_ERR(memblkenc->disk);
    }

    memblkenc->disk->major = memblkenc->major;
    memblkenc->disk->first_minor = 0;
    memblkenc->disk->minors = 1;
    memblkenc->disk->fops = &memdiskenc_fops;
    memblkenc->disk->private_data = memblkenc;
    snprintf(memblkenc->disk->disk_name, DISK_NAME_LEN, MEMBLKENC_DEVICE_NAME);
    
    set_capacity(memblkenc->disk, memblkenc->memsize >> SECTOR_SHIFT);

    ret = add_disk(memblkenc->disk);
    if(ret < 0)
    {
        pr_err("add %s disk failed\n", MEMBLKENC_DEVICE_NAME);
        put_disk(memblkenc->disk);
        unregister_blkdev(memblkenc->major, MEMBLKENC_DEVICE_NAME);
        return ret;
    }

    pr_info("memblk init success, block device start address %llx\n", (unsigned long long)memblkenc->vaddr);

    return 0;
}

static void memblkenc_remove(struct platform_device *pdev)
{
    del_gendisk(memblkenc->disk);
    put_disk(memblkenc->disk);
    unregister_blkdev(memblkenc->major, MEMBLKENC_DEVICE_NAME);
    pr_info("memory block disk released\n");

    return ;
}

static const struct of_device_id memblkenc_ids[] = {
    { .compatible = "pzx,memblkenc" },
    { }
};

static struct platform_driver memblkenc_drv = {
    .probe = memblkenc_probe,
    .remove = memblkenc_remove,
    .driver = {
        .name = "memblkenc",
        .of_match_table = memblkenc_ids,
    },
};

module_platform_driver(memblkenc_drv);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("pzx, pzxiong9865@gmail.com");
MODULE_DESCRIPTION("a memory block driver");