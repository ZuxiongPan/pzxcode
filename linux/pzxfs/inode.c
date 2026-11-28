// SPDX-License-Identifier: GPL-2.0
/*
 * pzxfs inode 与块管理
 *
 * 这个文件里只做两件事：
 *   1. 在「磁盘 inode」和「VFS inode」之间搬运字段；
 *   2. 位图分配/释放、逻辑块号 -> 物理块号映射。
 *
 * 块映射规则（和 ext2 一样的三级结构，只是砍掉了二级间接）：
 *   逻辑块 0  ~ 11          -> i_direct[0..11]
 *   逻辑块 12 ~ 12+1023     -> i_indirect 指向的间接块里的 1024 个 u32
 *   再往后                  -> 不支持（PZXFS_MAX_FILESIZE）
 */
#include "pzxfs.h"

static struct kmem_cache *pzxfs_inode_cachep;

static void pzxfs_inode_init_once(void *p)
{
	struct pzxfs_inode_info *ei = p;

	inode_init_once(&ei->vfs_inode);
}

int __init pzxfs_init_inode_cache(void)
{
	pzxfs_inode_cachep = kmem_cache_create("pzxfs_inode_cache",
					       sizeof(struct pzxfs_inode_info), 0,
					       SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
					       pzxfs_inode_init_once);
	if (!pzxfs_inode_cachep) {
		pr_err("pzxfs: unable to create inode cache\n");
		return -ENOMEM;
	}
	return 0;
}

struct inode *pzxfs_alloc_inode(struct super_block *sb)
{
	struct pzxfs_inode_info *ei;

	ei = alloc_inode_sb(sb, pzxfs_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;

	/* 构造函数只在 slab 第一次创建时跑，复用旧对象时必须自己清 */
	memset(ei->i_direct, 0, sizeof(ei->i_direct));
	ei->i_indirect = 0;
	return &ei->vfs_inode;
}

void pzxfs_destroy_inode(struct inode *inode)
{
	kmem_cache_free(pzxfs_inode_cachep, PZXFS_I(inode));
}

/* ------------------------------------------------------------------ */
/* 位图操作                                                            */
/*                                                                     */
/* 两个位图都完整落在一个 4K 块里，所以不用担心跨块搜索。               */
/* 每次分配/释放都立刻 sync_dirty_buffer，是为了让你 hexdump 时能马上   */
/* 看到变化；真实文件系统会攒批，交给回写线程。                         */
/* ------------------------------------------------------------------ */

static int pzxfs_bitmap_alloc(struct super_block *sb, pzxfs_u32 bitmap_block,
			      unsigned long nbits, unsigned long *hint)
{
	struct buffer_head *bh;
	unsigned long *bitmap;
	unsigned long bit;

	bh = sb_bread(sb, bitmap_block);
	if (!bh)
		return -EIO;
	bitmap = (unsigned long *)bh->b_data;

	bit = find_next_zero_bit(bitmap, nbits, *hint);
	if (bit >= nbits)
		bit = find_first_zero_bit(bitmap, nbits);
	if (bit >= nbits) {
		brelse(bh);
		return -ENOSPC;
	}

	__set_bit(bit, bitmap);
	*hint = bit + 1;

	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);
	return (int)bit;
}

static void pzxfs_bitmap_free(struct super_block *sb, pzxfs_u32 bitmap_block,
			      unsigned long bit)
{
	struct buffer_head *bh;

	bh = sb_bread(sb, bitmap_block);
	if (!bh)
		return;

	__clear_bit(bit, (unsigned long *)bh->b_data);
	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);
}

/* ------------------------------------------------------------------ */
/* 数据块分配                                                          */
/* ------------------------------------------------------------------ */

/*
 * 分配一个数据块。zero 非 0 时把新块清零（间接块、目录块必须清零，
 * 否则里面残留的是上一个使用者留下的垃圾数据）。
 *
 * 注意：块位图里第 N 位就对应第 N 块，是 1:1 映射，因为位图从块 0 开始算。
 */
pzxfs_u32 pzxfs_alloc_block(struct inode *inode, int zero)
{
	struct super_block *sb = inode->i_sb;
	struct pzxfs_sb_info *sbi = PZXFS_SB(sb);
	struct buffer_head *bh;
	int bit;

	bit = pzxfs_bitmap_alloc(sb, sbi->s_bbitmap, sbi->s_nblocks,
				 &sbi->s_bbitmap_hint);
	if (bit < 0)
		return 0;

	if (zero) {
		bh = sb_bread(sb, (pzxfs_u32)bit);
		if (!bh) {
			pzxfs_bitmap_free(sb, sbi->s_bbitmap, bit);
			return 0;
		}
		memset(bh->b_data, 0, PZXFS_BLOCK_SIZE);
		mark_buffer_dirty(bh);
		sync_dirty_buffer(bh);
		brelse(bh);
	}

	if (sbi->s_free_blocks)
		sbi->s_free_blocks--;
	/* VFS 的 i_blocks 单位是 512 字节扇区 */
	inode->i_blocks += PZXFS_BLOCK_SIZE >> PZXFS_SECTOR_SHIFT;
	return (pzxfs_u32)bit;
}

void pzxfs_free_block(struct inode *inode, pzxfs_u32 block)
{
	struct pzxfs_sb_info *sbi = PZXFS_SB(inode->i_sb);

	if (!block)
		return;

	pzxfs_bitmap_free(inode->i_sb, sbi->s_bbitmap, block);
	sbi->s_free_blocks++;
	inode->i_blocks -= PZXFS_BLOCK_SIZE >> PZXFS_SECTOR_SHIFT;
	if ((long)inode->i_blocks < 0)
		inode->i_blocks = 0;
}

/*
 * 逻辑块号 -> 物理块号。create 为 0 时只查询，未分配就返回 0。
 * 返回值 0 表示「这里是空洞」（读的时候填 0，写的时候按需分配）。
 */
pzxfs_u32 pzxfs_bmap(struct inode *inode, unsigned long block, int create)
{
	struct pzxfs_inode_info *ei = PZXFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct buffer_head *bh;
	pzxfs_u32 *ptrs, phys;

	if (block < PZXFS_DIRECT_BLOCKS) {
		if (!ei->i_direct[block] && create) {
			phys = pzxfs_alloc_block(inode, 1);
			if (!phys)
				return 0;
			ei->i_direct[block] = phys;
			mark_inode_dirty(inode);
		}
		return ei->i_direct[block];
	}

	block -= PZXFS_DIRECT_BLOCKS;
	if (block >= PZXFS_PTRS_PER_BLOCK)
		return 0;	/* 超出单级间接能表示的范围 */

	if (!ei->i_indirect) {
		if (!create)
			return 0;
		phys = pzxfs_alloc_block(inode, 1);
		if (!phys)
			return 0;
		ei->i_indirect = phys;
		mark_inode_dirty(inode);
	}

	bh = sb_bread(sb, ei->i_indirect);
	if (!bh)
		return 0;
	ptrs = (pzxfs_u32 *)bh->b_data;

	phys = ptrs[block];
	if (!phys && create) {
		phys = pzxfs_alloc_block(inode, 1);
		if (phys) {
			ptrs[block] = phys;
			mark_buffer_dirty(bh);
			sync_dirty_buffer(bh);
		}
	}
	brelse(bh);
	return phys;
}

/*
 * 把文件截短到 newsize。
 *
 * 这里刻意不调用 mark_inode_dirty：evict_inode() 里也要用它来释放块，
 * 那时 inode 已经在被销毁，不能再往回写队列里塞。
 */
void pzxfs_truncate(struct inode *inode, loff_t newsize)
{
	struct pzxfs_inode_info *ei = PZXFS_I(inode);
	struct super_block *sb = inode->i_sb;
	loff_t oldsize = i_size_read(inode);
	unsigned long old_blocks, first_keep, i;
	struct buffer_head *ibh = NULL;

	if (newsize >= oldsize) {
		/* 变长不分配块，空洞读出来就是 0；但 i_size 必须跟着变大 */
		i_size_write(inode, newsize);
		return;
	}

	old_blocks = DIV_ROUND_UP(oldsize, PZXFS_BLOCK_SIZE);
	first_keep = DIV_ROUND_UP(newsize, PZXFS_BLOCK_SIZE);

	/* 1. 释放 [first_keep, old_blocks) 覆盖的所有块，并清掉 inode 里的指针 */
	for (i = first_keep; i < old_blocks; i++) {
		pzxfs_u32 phys = pzxfs_bmap(inode, i, 0);

		if (!phys)
			continue;

		if (i < PZXFS_DIRECT_BLOCKS) {
			ei->i_direct[i] = 0;
		} else if (ei->i_indirect) {
			if (!ibh)
				ibh = sb_bread(sb, ei->i_indirect);
			if (ibh)
				((pzxfs_u32 *)ibh->b_data)[i - PZXFS_DIRECT_BLOCKS] = 0;
		}
		pzxfs_free_block(inode, phys);
	}

	/* 2. 间接块本身：所有间接指针都不用了，才回收这块 */
	if (ei->i_indirect && first_keep <= PZXFS_DIRECT_BLOCKS) {
		if (!ibh)
			ibh = sb_bread(sb, ei->i_indirect);
		if (ibh) {
			memset(ibh->b_data, 0, PZXFS_BLOCK_SIZE);
			mark_buffer_dirty(ibh);
			sync_dirty_buffer(ibh);
		}
		pzxfs_free_block(inode, ei->i_indirect);
		ei->i_indirect = 0;
	} else if (ibh) {
		mark_buffer_dirty(ibh);
		sync_dirty_buffer(ibh);
	}
	brelse(ibh);

	/* 3. 新文件尾所在块的剩余部分清零，避免下次写时读到上一个文件的内容 */
	if (newsize & PZXFS_BLOCK_MASK) {
		pzxfs_u32 phys = pzxfs_bmap(inode, newsize >> PZXFS_BLOCK_BITS, 0);

		if (phys) {
			struct buffer_head *bh = sb_bread(sb, phys);

			if (bh) {
				memset(bh->b_data + (newsize & PZXFS_BLOCK_MASK), 0,
				       PZXFS_BLOCK_SIZE - (newsize & PZXFS_BLOCK_MASK));
				mark_buffer_dirty(bh);
				sync_dirty_buffer(bh);
				brelse(bh);
			}
		}
	}

	i_size_write(inode, newsize);
}

/* ------------------------------------------------------------------ */
/* inode 读取 / 回写                                                   */
/* ------------------------------------------------------------------ */

static inline unsigned long pzxfs_itable_block(struct pzxfs_sb_info *sbi, unsigned long ino)
{
	return sbi->s_itable + (ino - 1) / PZXFS_INODES_PER_BLOCK;
}

static inline unsigned long pzxfs_itable_offset(unsigned long ino)
{
	return ((ino - 1) % PZXFS_INODES_PER_BLOCK) * PZXFS_INODE_SIZE;
}

/*
 * 从磁盘读一个 inode 进来。这就是你在 open 链里看到的 iget_locked：
 * 先查 icache，没有就返回一个 I_NEW 状态的新 inode，由文件系统负责填充，
 * 填完必须 unlock_new_inode() 把等待者叫醒。
 */
struct inode *pzxfs_iget(struct super_block *sb, unsigned long ino)
{
	struct pzxfs_sb_info *sbi = PZXFS_SB(sb);
	struct pzxfs_inode_info *ei;
	struct pzxfs_inode *di;
	struct buffer_head *bh;
	struct inode *inode;
	struct timespec64 ts;
	int err = -EIO;

	if (ino < PZXFS_ROOT_INO || ino > sbi->s_ninodes)
		return ERR_PTR(-EINVAL);

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;		/* 缓存里已有，直接用 */

	ei = PZXFS_I(inode);

	bh = sb_bread(sb, pzxfs_itable_block(sbi, ino));
	if (!bh)
		goto failed;
	di = (struct pzxfs_inode *)(bh->b_data + pzxfs_itable_offset(ino));

	inode->i_mode	= di->i_mode;
	set_nlink(inode, di->i_links_count);
	inode->i_size	= di->i_size;
	/* 磁盘上存 4K 块个数，VFS 要 512 字节扇区个数 */
	inode->i_blocks	= (blkcnt_t)di->i_blocks << (PZXFS_BLOCK_BITS - PZXFS_SECTOR_SHIFT);

	ts = (struct timespec64){ .tv_sec = di->i_mtime, .tv_nsec = 0 };
	inode_set_mtime_to_ts(inode, ts);
	inode_set_atime_to_ts(inode, ts);
	inode_set_ctime_to_ts(inode, ts);

	memcpy(ei->i_direct, di->i_direct, sizeof(ei->i_direct));
	ei->i_indirect = di->i_indirect;
	brelse(bh);

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_op  = &pzxfs_file_inode_operations;
		inode->i_fop = &pzxfs_file_operations;
		break;
	case S_IFDIR:
		inode->i_op  = &pzxfs_dir_inode_operations;
		inode->i_fop = &pzxfs_dir_operations;
		break;
	default:
		/* 第一版不支持设备节点/符号链接/管道，遇到就当坏 inode */
		pr_err("pzxfs: inode %lu has unsupported mode %o\n", ino, inode->i_mode);
		err = -EIO;
		goto failed;
	}

	unlock_new_inode(inode);
	return inode;

failed:
	iget_failed(inode);
	return ERR_PTR(err);
}

/*
 * 把 inode 写回磁盘。VFS 在 mark_inode_dirty 之后的回写时机调用这里，
 * sync/umount 也会触发。为了让 hexdump 立刻看到结果，这里同步落盘。
 */
int pzxfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct super_block *sb = inode->i_sb;
	struct pzxfs_sb_info *sbi = PZXFS_SB(sb);
	struct pzxfs_inode_info *ei = PZXFS_I(inode);
	struct pzxfs_inode *di;
	struct buffer_head *bh;

	if (!inode->i_ino || inode->i_ino > sbi->s_ninodes)
		return 0;

	bh = sb_bread(sb, pzxfs_itable_block(sbi, inode->i_ino));
	if (!bh)
		return -EIO;
	di = (struct pzxfs_inode *)(bh->b_data + pzxfs_itable_offset(inode->i_ino));

	di->i_mode	  = inode->i_mode;
	di->i_links_count = inode->i_nlink;
	di->i_size	  = inode->i_size;
	di->i_blocks	  = inode->i_blocks >> (PZXFS_BLOCK_BITS - PZXFS_SECTOR_SHIFT);
	di->i_mtime	  = (pzxfs_u32)inode_get_mtime(inode).tv_sec;
	memcpy(di->i_direct, ei->i_direct, sizeof(di->i_direct));
	di->i_indirect	  = ei->i_indirect;

	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);
	return 0;
}

/*
 * 新建一个 inode：占 inode 号 -> 造 VFS inode -> 挂进 icache -> 标脏。
 * 注意这里用的是 new_inode()，不是 iget_locked()，因为磁盘上还没有它。
 */
struct inode *pzxfs_new_inode(struct mnt_idmap *idmap, struct inode *dir, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct pzxfs_sb_info *sbi = PZXFS_SB(sb);
	struct pzxfs_inode_info *ei;
	struct inode *inode;
	struct timespec64 now;
	int bit;

	bit = pzxfs_bitmap_alloc(sb, sbi->s_ibitmap, sbi->s_ninodes,
				 &sbi->s_ibitmap_hint);
	if (bit < 0)
		return ERR_PTR(bit);

	inode = new_inode(sb);
	if (!inode) {
		pzxfs_bitmap_free(sb, sbi->s_ibitmap, bit);
		return ERR_PTR(-ENOMEM);
	}

	ei = PZXFS_I(inode);
	memset(ei->i_direct, 0, sizeof(ei->i_direct));
	ei->i_indirect = 0;

	inode->i_ino = bit + 1;
	inode_init_owner(idmap, inode, dir, mode);
	inode->i_size	= 0;
	inode->i_blocks	= 0;
	set_nlink(inode, 1);

	now = current_time(inode);
	inode_set_atime_to_ts(inode, now);
	inode_set_mtime_to_ts(inode, now);
	inode_set_ctime_to_ts(inode, now);

	switch (mode & S_IFMT) {
	case S_IFREG:
		inode->i_op  = &pzxfs_file_inode_operations;
		inode->i_fop = &pzxfs_file_operations;
		break;
	case S_IFDIR:
		inode->i_op  = &pzxfs_dir_inode_operations;
		inode->i_fop = &pzxfs_dir_operations;
		break;
	default:
		iput(inode);
		pzxfs_bitmap_free(sb, sbi->s_ibitmap, bit);
		return ERR_PTR(-EINVAL);
	}

	insert_inode_hash(inode);
	mark_inode_dirty(inode);

	if (sbi->s_free_inodes)
		sbi->s_free_inodes--;
	return inode;
}

/* 只还 inode 号，不动数据块（数据块由 truncate 负责） */
void pzxfs_free_inode(struct inode *inode)
{
	struct pzxfs_sb_info *sbi = PZXFS_SB(inode->i_sb);

	if (!inode->i_ino)
		return;
	pzxfs_bitmap_free(inode->i_sb, sbi->s_ibitmap, inode->i_ino - 1);
	sbi->s_free_inodes++;
}

void pzxfs_evict_inode(struct inode *inode)
{
	/*
	 * 第一版没有 unlink()，所以 i_nlink 一直是 1，这里的回收逻辑只会
	 * 在 create 失败回滚（先 dec 到 0 再 iput）时走到。
	 */
	truncate_inode_pages_final(&inode->i_data);

	if (!inode->i_nlink && !is_bad_inode(inode)) {
		pzxfs_truncate(inode, 0);
		pzxfs_free_inode(inode);
	}
	clear_inode(inode);
}
