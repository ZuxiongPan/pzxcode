#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/of_reserved_mem.h>

#define MEMBLK_DEVICE_NAME "memblk"

struct memblk_device {
    void __iomem *vaddr;
    resource_size_t phyaddr;
    resource_size_t memsize;
    int major;
    struct gendisk *disk;
};

static struct memblk_device *memblk = NULL;

static void memblk_submit_bio(struct bio *bio)
{
    struct memblk_device *mbd = bio->bi_bdev->bd_disk->private_data;
    struct bio_vec bvec;
    struct bvec_iter biter;
    sector_t sector = bio->bi_iter.bi_sector;
    size_t offset = sector << SECTOR_SHIFT;

    bio_for_each_segment(bvec, bio, biter)
    {
        void *addr = kmap_atomic(bvec.bv_page) + bvec.bv_offset;

        if(unlikely(offset + bvec.bv_len > mbd->memsize))
        {
            kunmap_atomic(addr);
            bio_io_error(bio);
            return ;
        }

        if(WRITE == bio_data_dir(bio))
        {
            memcpy(mbd->vaddr + offset, addr, bvec.bv_len);
        }
        else
        {
            memcpy(addr, mbd->vaddr + offset, bvec.bv_len);
        }

        offset += bvec.bv_len;
        kunmap_atomic(addr);
    }

    bio_endio(bio);
    return ;
}

const struct block_device_operations memdisk_fops = {
    .owner = THIS_MODULE,
    .submit_bio = memblk_submit_bio,
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
    lim.features |= BLK_FEAT_SYNCHRONOUS;
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

    memblk->disk = blk_alloc_disk(&lim, NUMA_NO_NODE);
    if(IS_ERR(memblk->disk))
    {
        pr_err("failed to allocate disk for %s\n", MEMBLK_DEVICE_NAME);
        unregister_blkdev(memblk->major, MEMBLK_DEVICE_NAME);
        return PTR_ERR(memblk->disk);
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
        unregister_blkdev(memblk->major, MEMBLK_DEVICE_NAME);
        return ret;
    }

    pr_info("memblk init success, block device start address %llx\n", (unsigned long long)memblk->vaddr);

    return 0;
}

static void memblk_remove(struct platform_device *pdev)
{
    del_gendisk(memblk->disk);
    put_disk(memblk->disk);
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