#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/of_reserved_mem.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/crypto.h>

#define MEMBLKENC_DEVICE_NAME "memblkenc"

struct memblkenc_device {
    void __iomem *vaddr;
    resource_size_t phyaddr;
    resource_size_t memsize;
    int major;
    struct gendisk *disk;
    struct crypto_skcipher *tfm;
};

static struct memblkenc_device *memblkenc = NULL;
const char *key = "0123456789abcdef0123456789abcdef";

static int do_aes_crypt(struct memblkenc_device *mbed, void *data, size_t len, sector_t sector, bool encry)
{
    struct skcipher_request *req;
    struct scatterlist sg;
    int ret = 0;
    u8 tweak[16];

    DECLARE_CRYPTO_WAIT(wait);
    memset(tweak, 0, 16);
    *(sector_t *)tweak = sector;

    req = skcipher_request_alloc(mbed->tfm, GFP_ATOMIC);
    if(NULL == req)
    {
        return -ENOMEM;
    }

    sg_init_one(&sg, data, len);

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, len, (void *)tweak);
    ret = encry ? crypto_skcipher_encrypt(req) : crypto_skcipher_decrypt(req);
    ret = crypto_wait_req(ret, &wait);

    skcipher_request_free(req);
    return ret;
}

static void memblkenc_submit_bio(struct bio *bio)
{
    struct memblkenc_device *mbed = bio->bi_bdev->bd_disk->private_data;
    struct bio_vec bvec;
    struct bvec_iter biter;
    sector_t iter_sector = bio->bi_iter.bi_sector;

    bio_for_each_segment(bvec, bio, biter)
    {
        void *addr = kmap_atomic(bvec.bv_page) + bvec.bv_offset;
        size_t bvec_len = bvec.bv_len;
        void *curr_addr = addr;

        while(bvec_len > 0)
        {
            size_t chunk_len = min_t(size_t, bvec_len, SECTOR_SIZE);
            size_t disk_offset = iter_sector << SECTOR_SHIFT;

            if(WRITE == bio_data_dir(bio))
            {
                do_aes_crypt(mbed, curr_addr, chunk_len, iter_sector, true);
                memcpy_toio(mbed->vaddr + disk_offset, curr_addr, chunk_len);
                do_aes_crypt(mbed, curr_addr, chunk_len, iter_sector, false);
            }
            else
            {
                memcpy_fromio(curr_addr, mbed->vaddr + disk_offset, chunk_len);
                do_aes_crypt(mbed, curr_addr, chunk_len, iter_sector, false);
            }

            curr_addr += chunk_len;
            bvec_len -= chunk_len;
            iter_sector += (chunk_len >> SECTOR_SHIFT);
        }

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

    memblkenc->tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
    if(IS_ERR(memblkenc->tfm))
    {
        pr_err("cannot alloc aes-cbc crypto skcipher\n");
        return PTR_ERR(memblkenc->tfm);
    }

    ret = crypto_skcipher_setkey(memblkenc->tfm, key, 32);
    if(ret < 0)
    {
        pr_err("failed to set aes key \n");
        crypto_free_skcipher(memblkenc->tfm);
        return ret;
    }

    memblkenc->major = register_blkdev(0, MEMBLKENC_DEVICE_NAME);
    if(memblkenc->major < 0)
    {
        pr_err("register %s block device failed\n", MEMBLKENC_DEVICE_NAME);
        crypto_free_skcipher(memblkenc->tfm);
        return -ENODEV;
    }

    memblkenc->disk = blk_alloc_disk(&lim, NUMA_NO_NODE);
    if(IS_ERR(memblkenc->disk))
    {
        pr_err("failed to allocate disk for %s\n", MEMBLKENC_DEVICE_NAME);
        unregister_blkdev(memblkenc->major, MEMBLKENC_DEVICE_NAME);
        crypto_free_skcipher(memblkenc->tfm);
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
        crypto_free_skcipher(memblkenc->tfm);
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
    crypto_free_skcipher(memblkenc->tfm);
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