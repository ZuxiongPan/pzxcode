// SPDX-License-Identifier: GPL-2.0
/*
 * pzxfs —— 一个用来打通 open/read/write/close 全链路的教学文件系统
 *
 * 目标不是做得像 ext4，而是让「一次 write 到底改了哪几个块」变得可见：
 * 没有任何缓存层包裹，每一次 sb_bread / sync_dirty_buffer 都能在
 * hexdump -C /dev/memblk 里找到对应字节。
 *
 * 磁盘布局（8MB 的 /dev/memblk，4K 块 -> 2048 块）：
 *
 *   块 0        超级块                 magic 'PXFS' + 布局参数
 *   块 1        inode 位图             512 bit，1 表示已用
 *   块 2        数据块位图             2048 bit，1 表示已用
 *   块 3~18     inode 表               16 块 × 32 个 = 512 个 inode
 *   块 19       根目录数据块           128 个目录项（. 和 .. 已写入）
 *   块 20~2047  普通数据块
 *
 * 挂载/使用：
 *   mount -t pzxfs -o format /dev/memblk /mnt   # 第一次：格式化并挂载
 *   umount /mnt && mount -t pzxfs /dev/memblk /mnt
 *   echo hello > /mnt/a.txt
 *   sync
 *   hexdump -C /dev/memblk | head     # 块 0 能看到 50 58 46 53 ("PXFS")
 */
#include "pzxfs.h"

/* ------------------------------------------------------------------ */
/* 格式化                                                              */
/* ------------------------------------------------------------------ */

static struct buffer_head *pzxfs_get_zeroed_block(struct super_block *sb,
						  unsigned long block, int *err)
{
	struct buffer_head *bh = sb_bread(sb, block);

	if (!bh) {
		*err = -EIO;
		return NULL;
	}
	memset(bh->b_data, 0, PZXFS_BLOCK_SIZE);
	return bh;
}

static void pzxfs_commit_block(struct buffer_head *bh)
{
	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);
}

/*
 * 在块设备上建立 pzxfs 的初始结构。调用前 sb_set_blocksize() 必须已经生效。
 * 用户态工具 mkfs/mkfs.pzxfs.c 做的是同一件事，两边布局必须保持一致。
 */
static int pzxfs_format(struct super_block *sb, unsigned long dev_blocks)
{
	struct pzxfs_super_block *dsb;
	struct pzxfs_inode *di;
	struct pzxfs_dirent *de;
	struct buffer_head *bh;
	unsigned long nblocks = dev_blocks, blk;
	int err = 0;

	/* 位图只有 4K = 32768 bit，最多管 32768 个块（128MB） */
	if (nblocks > 32768UL)
		nblocks = 32768UL;
	if (nblocks < PZXFS_FIRST_DATA_BLOCK + 8)
		return -ENOSPC;

	pr_info("pzxfs: 正在格式化 %s：%lu 个块（%lu 字节）\n",
		sb->s_id, nblocks, nblocks * PZXFS_BLOCK_SIZE);

	/* 1. 超级块（块 0） */
	bh = pzxfs_get_zeroed_block(sb, PZXFS_SB_BLOCK, &err);
	if (!bh)
		return err;
	dsb = (struct pzxfs_super_block *)bh->b_data;
	dsb->s_magic		= PZXFS_MAGIC;
	dsb->s_version		= PZXFS_VERSION;
	dsb->s_blocksize		= PZXFS_BLOCK_SIZE;
	dsb->s_nblocks		= nblocks;
	dsb->s_ninodes		= PZXFS_MAX_INODES;
	dsb->s_free_blocks	= nblocks - PZXFS_FIRST_DATA_BLOCK;
	dsb->s_free_inodes	= PZXFS_MAX_INODES - 1;	/* 根目录占 1 个 */
	dsb->s_root_ino		= PZXFS_ROOT_INO;
	dsb->s_ibitmap		= PZXFS_IBITMAP_BLOCK;
	dsb->s_bbitmap		= PZXFS_BBITMAP_BLOCK;
	dsb->s_itable		= PZXFS_ITABLE_BLOCK;
	dsb->s_itable_blocks	= PZXFS_ITABLE_BLOCKS;
	dsb->s_first_data_block	= PZXFS_FIRST_DATA_BLOCK;
	dsb->s_mtime		= (pzxfs_u32)ktime_get_real_seconds();
	memcpy(dsb->s_volume, "pzxfs", 6);
	pzxfs_commit_block(bh);

	/* 2. inode 位图：只把 0 号 bit（根 inode）置 1 */
	bh = pzxfs_get_zeroed_block(sb, PZXFS_IBITMAP_BLOCK, &err);
	if (!bh)
		return err;
	__set_bit(0, (unsigned long *)bh->b_data);
	pzxfs_commit_block(bh);

	/* 3. 数据块位图：0 ~ FIRST_DATA_BLOCK-1 全是元数据，全部置 1 */
	bh = pzxfs_get_zeroed_block(sb, PZXFS_BBITMAP_BLOCK, &err);
	if (!bh)
		return err;
	for (blk = 0; blk < PZXFS_FIRST_DATA_BLOCK; blk++)
		__set_bit(blk, (unsigned long *)bh->b_data);
	pzxfs_commit_block(bh);

	/* 4. inode 表清零 */
	for (blk = PZXFS_ITABLE_BLOCK;
	     blk < PZXFS_ITABLE_BLOCK + PZXFS_ITABLE_BLOCKS; blk++) {
		bh = pzxfs_get_zeroed_block(sb, blk, &err);
		if (!bh)
			return err;
		pzxfs_commit_block(bh);
	}

	/* 5. 根 inode：放在 inode 表第一个块的第 0 个槽位 */
	bh = sb_bread(sb, PZXFS_ITABLE_BLOCK);
	if (!bh)
		return -EIO;
	di = (struct pzxfs_inode *)bh->b_data;
	di->i_mode	= S_IFDIR | 0755;
	di->i_links_count = 2;			/* "." 一个，".." 一个 */
	di->i_size	= PZXFS_BLOCK_SIZE;	/* 一个目录块 = 128 个目录项 */
	di->i_blocks	= 1;			/* 磁盘记的是 4K 块个数 */
	di->i_mtime	= (pzxfs_u32)ktime_get_real_seconds();
	di->i_direct[0]	= PZXFS_ROOT_BLOCK;
	pzxfs_commit_block(bh);

	/* 6. 根目录数据块："." 和 ".." 都指向根自己 */
	bh = pzxfs_get_zeroed_block(sb, PZXFS_ROOT_BLOCK, &err);
	if (!bh)
		return err;
	de = (struct pzxfs_dirent *)bh->b_data;
	de[0].inode = PZXFS_ROOT_INO;
	strcpy(de[0].name, ".");
	de[1].inode = PZXFS_ROOT_INO;
	strcpy(de[1].name, "..");
	pzxfs_commit_block(bh);

	/*
	 * 7. 其余数据块不用清零：位图里已经把它们标成空闲，下次分配时
	 *    pzxfs_alloc_block(inode, 1) 会先清零再用。
	 */
	return 0;
}

/* ------------------------------------------------------------------ */
/* 挂载                                                                */
/* ------------------------------------------------------------------ */

static void pzxfs_count_free(struct super_block *sb)
{
	struct pzxfs_sb_info *sbi = PZXFS_SB(sb);
	struct buffer_head *bh;
	unsigned long used;

	bh = sb_bread(sb, sbi->s_ibitmap);
	if (bh) {
		used = bitmap_weight((unsigned long *)bh->b_data, sbi->s_ninodes);
		sbi->s_free_inodes = sbi->s_ninodes - used;
		brelse(bh);
	}

	bh = sb_bread(sb, sbi->s_bbitmap);
	if (bh) {
		used = bitmap_weight((unsigned long *)bh->b_data, sbi->s_nblocks);
		sbi->s_free_blocks = sbi->s_nblocks - used;
		brelse(bh);
	}

	sbi->s_ibitmap_hint = 1;
	sbi->s_bbitmap_hint = sbi->s_first_data_block;
}

static int pzxfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
	struct pzxfs_fs_context *ctx = fc->fs_private;
	struct pzxfs_sb_info *sbi;
	struct pzxfs_super_block *dsb;
	struct buffer_head *bh;
	struct inode *root;
	unsigned long dev_blocks;
	pzxfs_u32 version, blocksize, itable_blocks;
	int err;

	/* 必须在任何 sb_bread 之前设置，否则块号会按 1K 解释 */
	if (!sb_set_blocksize(sb, PZXFS_BLOCK_SIZE)) {
		errorf(fc, "pzxfs: 无法把块大小设为 %u\n", PZXFS_BLOCK_SIZE);
		return -EINVAL;
	}

	dev_blocks = bdev_nr_bytes(sb->s_bdev) >> PZXFS_BLOCK_BITS;
	if (dev_blocks < PZXFS_FIRST_DATA_BLOCK + 8) {
		errorf(fc, "pzxfs: %s 太小（只有 %lu 个 4K 块）\n",
		       sb->s_id, dev_blocks);
		return -ENOSPC;
	}

	bh = sb_bread(sb, PZXFS_SB_BLOCK);
	if (!bh)
		return -EIO;

	if (((struct pzxfs_super_block *)bh->b_data)->s_magic != PZXFS_MAGIC) {
		brelse(bh);
		if (!ctx->format) {
			errorf(fc, "pzxfs: %s 上没有 pzxfs 超级块，"
			       "先执行 mount -o format 格式化\n", sb->s_id);
			return -EINVAL;
		}
		err = pzxfs_format(sb, dev_blocks);
		if (err)
			return err;
		bh = sb_bread(sb, PZXFS_SB_BLOCK);
		if (!bh)
			return -EIO;
	}

	dsb = (struct pzxfs_super_block *)bh->b_data;
	version	     = dsb->s_version;
	blocksize    = dsb->s_blocksize;
	itable_blocks = dsb->s_itable_blocks;
	if (version != PZXFS_VERSION ||
	    blocksize != PZXFS_BLOCK_SIZE ||
	    itable_blocks != PZXFS_ITABLE_BLOCKS) {
		brelse(bh);
		errorf(fc, "pzxfs: 超级块不兼容（version=%u blocksize=%u）\n",
		       version, blocksize);
		return -EINVAL;
	}

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi) {
		brelse(bh);
		return -ENOMEM;
	}
	/*
	 * 两个地方都挂着 sbi：
	 *   sb->s_fs_info —— 挂载期间正常路径用，卸载时 put_super() 负责释放
	 *   fc->s_fs_info —— 只用于「fill_super 失败」的兜底：此时 sb->s_root
	 *                    还是 NULL，generic_shutdown_super() 不会调
	 *                    put_super()，只能靠 free_fs_context() 释放
	 * 成功时把 fc->s_fs_info 清掉，避免重复释放。
	 */
	sb->s_fs_info = sbi;
	fc->s_fs_info = sbi;
	sb->s_op = &pzxfs_sops;

	sbi->s_nblocks		 = dsb->s_nblocks;
	sbi->s_ninodes		 = dsb->s_ninodes;
	sbi->s_ibitmap		 = dsb->s_ibitmap;
	sbi->s_bbitmap		 = dsb->s_bbitmap;
	sbi->s_itable		 = dsb->s_itable;
	sbi->s_first_data_block	 = dsb->s_first_data_block;
	brelse(bh);

	if (sbi->s_nblocks > dev_blocks ||
	    sbi->s_ninodes > PZXFS_MAX_INODES) {
		errorf(fc, "pzxfs: 超级块记录的大小超出设备容量\n");
		return -EINVAL;
	}

	pzxfs_count_free(sb);

	sb->s_magic	= PZXFS_MAGIC;
	sb->s_maxbytes	= PZXFS_MAX_FILESIZE;
	sb->s_time_gran	= 1;
	sb->s_flags	|= SB_NOSEC;

	root = pzxfs_iget(sb, PZXFS_ROOT_INO);
	if (IS_ERR(root)) {
		errorf(fc, "pzxfs: 读根 inode 失败: %ld\n", PTR_ERR(root));
		return PTR_ERR(root);
	}

	sb->s_root = d_make_root(root);		/* 失败时它会自己 iput(root) */
	if (!sb->s_root)
		return -ENOMEM;

	fc->s_fs_info = NULL;			/* 移交成功，不再由 fc 释放 */

	pr_info("pzxfs: %s 挂载成功：%lu 块，%lu 个 inode，空闲 %lu 块/%lu inode\n",
		sb->s_id, sbi->s_nblocks, sbi->s_ninodes,
		sbi->s_free_blocks, sbi->s_free_inodes);
	return 0;
}

static int pzxfs_get_tree(struct fs_context *fc)
{
	return get_tree_bdev(fc, pzxfs_fill_super);
}

/* ------------------------------------------------------------------ */
/* 挂载参数：-o format                                                 */
/* ------------------------------------------------------------------ */

enum pzxfs_param {
	Opt_format,
};

static const struct fs_parameter_spec pzxfs_parameters[] = {
	fsparam_flag("format", Opt_format),
	{}
};

static int pzxfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
	struct pzxfs_fs_context *ctx = fc->fs_private;
	struct fs_parse_result result;
	int opt;

	opt = fs_parse(fc, pzxfs_parameters, param, &result);
	if (opt < 0)
		return opt;

	switch (opt) {
	case Opt_format:
		ctx->format = true;
		break;
	}
	return 0;
}

static void pzxfs_free_fs_context(struct fs_context *fc)
{
	kfree(fc->fs_private);
	/* 只有 fill_super 半途失败时这里才非空 */
	kfree(fc->s_fs_info);
}

static const struct fs_context_operations pzxfs_context_ops = {
	.parse_param	= pzxfs_parse_param,
	.get_tree	= pzxfs_get_tree,
	.free		= pzxfs_free_fs_context,
};

static int pzxfs_init_fs_context(struct fs_context *fc)
{
	struct pzxfs_fs_context *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	fc->fs_private = ctx;
	fc->ops = &pzxfs_context_ops;
	return 0;
}

/* ------------------------------------------------------------------ */
/* super_operations                                                    */
/* ------------------------------------------------------------------ */

static void pzxfs_put_super(struct super_block *sb)
{
	kfree(sb->s_fs_info);
	sb->s_fs_info = NULL;
}

static int pzxfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct pzxfs_sb_info *sbi = PZXFS_SB(dentry->d_sb);

	buf->f_type	= PZXFS_MAGIC;
	buf->f_bsize	= PZXFS_BLOCK_SIZE;
	buf->f_blocks	= sbi->s_nblocks;
	buf->f_bfree	= sbi->s_free_blocks;
	buf->f_bavail	= sbi->s_free_blocks;
	buf->f_files	= sbi->s_ninodes;
	buf->f_ffree	= sbi->s_free_inodes;
	buf->f_namelen	= PZXFS_NAME_LEN - 1;
	return 0;
}

/* 把内存里的空闲计数刷回超级块（umount / sync 时调用） */
static int pzxfs_sync_fs(struct super_block *sb, int wait)
{
	struct pzxfs_sb_info *sbi = PZXFS_SB(sb);
	struct pzxfs_super_block *dsb;
	struct buffer_head *bh;

	bh = sb_bread(sb, PZXFS_SB_BLOCK);
	if (!bh)
		return -EIO;

	dsb = (struct pzxfs_super_block *)bh->b_data;
	dsb->s_free_blocks = sbi->s_free_blocks;
	dsb->s_free_inodes = sbi->s_free_inodes;
	dsb->s_mtime	   = (pzxfs_u32)ktime_get_real_seconds();

	mark_buffer_dirty(bh);
	if (wait)
		sync_dirty_buffer(bh);
	brelse(bh);
	return 0;
}

const struct super_operations pzxfs_sops = {
	.alloc_inode	= pzxfs_alloc_inode,
	.destroy_inode	= pzxfs_destroy_inode,
	.write_inode	= pzxfs_write_inode,
	.evict_inode	= pzxfs_evict_inode,
	.put_super	= pzxfs_put_super,
	.statfs		= pzxfs_statfs,
	.sync_fs	= pzxfs_sync_fs,
};

/* ------------------------------------------------------------------ */
/* 注册                                                                */
/* ------------------------------------------------------------------ */

static struct file_system_type pzxfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "pzxfs",
	.init_fs_context = pzxfs_init_fs_context,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};

/*
 * 以 obj-y 编进内核，所以只有初始化、没有卸载：
 * 注销文件系统需要确保没有任何挂载点，对内置文件系统意义不大。
 */
static int __init pzxfs_init(void)
{
	int err;

	err = pzxfs_init_inode_cache();
	if (err)
		return err;

	err = register_filesystem(&pzxfs_fs_type);
	if (err) {
		pr_err("pzxfs: register_filesystem 失败: %d\n", err);
		return err;
	}

	pr_info("pzxfs: regietered (block size %u, inode limit %u, max file size %lu bytes)\n",
		PZXFS_BLOCK_SIZE, PZXFS_MAX_INODES,
		(unsigned long)PZXFS_MAX_FILESIZE);
	return 0;
}
module_init(pzxfs_init);
