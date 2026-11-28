// SPDX-License-Identifier: GPL-2.0
/*
 * pzxfs 目录操作：lookup / create / readdir
 *
 * 目录在磁盘上就是一段「固定 32 字节目录项」数组，放在 inode 的
 * direct[] 指向的数据块里。一个块 128 项，最多 12 个块 = 1536 项。
 *
 * 这里能看清 VFS 的两个不同入口：
 *   - open("/mnt/a") 解析路径时走 inode_operations->lookup（查目录项）
 *   - readdir/getdents64 时走 file_operations->iterate_shared（遍历目录项）
 * 两套代码路径完全不同，别混。
 */
#include "pzxfs.h"

/* ------------------------------------------------------------------ */
/* 目录项查找 / 追加                                                   */
/* ------------------------------------------------------------------ */

/* 找到返回 inode 号，找不到返回 0 */
static pzxfs_u32 pzxfs_find_entry(struct inode *dir, const struct qstr *name)
{
	struct super_block *sb = dir->i_sb;
	unsigned long blk, nblocks = DIV_ROUND_UP(dir->i_size, PZXFS_BLOCK_SIZE);
	pzxfs_u32 ino = 0;

	for (blk = 0; blk < nblocks && blk < PZXFS_DIRECT_BLOCKS; blk++) {
		struct buffer_head *bh;
		struct pzxfs_dirent *de;
		pzxfs_u32 phys;
		int i;

		phys = pzxfs_bmap(dir, blk, 0);
		if (!phys)
			continue;
		bh = sb_bread(sb, phys);
		if (!bh)
			return 0;

		for (i = 0; i < PZXFS_DIRENTS_PER_BLOCK; i++) {
			de = (struct pzxfs_dirent *)bh->b_data + i;
			if (!de->inode)
				continue;
			/* 目录项是 '\0' 结尾的，先比长度再比内容 */
			if (de->name[name->len] != '\0')
				continue;
			if (memcmp(de->name, name->name, name->len))
				continue;
			ino = de->inode;
			break;
		}
		brelse(bh);
		if (ino)
			break;
	}
	return ino;
}

/*
 * 把 (name -> ino) 写进目录。先找空槽，没有空槽就给目录追加一个数据块，
 * 这样目录能随文件数量增长（上限 12 个块）。
 */
static int pzxfs_add_entry(struct inode *dir, const struct qstr *name, pzxfs_u32 ino)
{
	struct super_block *sb = dir->i_sb;
	struct pzxfs_inode_info *ei = PZXFS_I(dir);
	unsigned long blk, nblocks = DIV_ROUND_UP(dir->i_size, PZXFS_BLOCK_SIZE);
	struct buffer_head *bh = NULL;
	struct pzxfs_dirent *de;
	pzxfs_u32 phys;
	int i, slot = -1;

	for (blk = 0; blk < nblocks && blk < PZXFS_DIRECT_BLOCKS; blk++) {
		phys = pzxfs_bmap(dir, blk, 0);
		if (!phys)
			continue;
		bh = sb_bread(sb, phys);
		if (!bh)
			return -EIO;
		for (i = 0; i < PZXFS_DIRENTS_PER_BLOCK; i++) {
			de = (struct pzxfs_dirent *)bh->b_data + i;
			if (!de->inode) {
				slot = i;
				break;
			}
		}
		if (slot >= 0)
			break;
		brelse(bh);
		bh = NULL;
	}

	if (slot < 0) {
		/* 目录满了：追加一个新块 */
		if (nblocks >= PZXFS_DIRECT_BLOCKS)
			return -ENOSPC;

		phys = pzxfs_alloc_block(dir, 1);
		if (!phys)
			return -ENOSPC;

		ei->i_direct[nblocks] = phys;
		i_size_write(dir, (nblocks + 1) * PZXFS_BLOCK_SIZE);
		mark_inode_dirty(dir);

		bh = sb_bread(sb, phys);
		if (!bh)
			return -EIO;
		slot = 0;
	}

	de = (struct pzxfs_dirent *)bh->b_data + slot;
	memset(de, 0, sizeof(*de));
	de->inode = ino;
	memcpy(de->name, name->name, name->len);	/* 剩下的字节已经是 0 */

	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);
	return 0;
}

/* ------------------------------------------------------------------ */
/* inode_operations                                                    */
/* ------------------------------------------------------------------ */

static struct dentry *pzxfs_lookup(struct inode *dir, struct dentry *dentry,
				   unsigned int flags)
{
	struct inode *inode = NULL;
	pzxfs_u32 ino;

	if (dentry->d_name.len >= PZXFS_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	ino = pzxfs_find_entry(dir, &dentry->d_name);
	if (ino) {
		inode = pzxfs_iget(dir->i_sb, ino);
		if (IS_ERR(inode))
			return ERR_CAST(inode);
	}
	/*
	 * 找不到就返回 NULL inode，VFS 会得到一个负 dentry。
	 * d_splice_alias 顺带处理了硬链接（同一个 inode 多个 dentry）的情况。
	 */
	return d_splice_alias(inode, dentry);
}

static int pzxfs_create(struct mnt_idmap *idmap, struct inode *dir,
			struct dentry *dentry, umode_t mode, bool excl)
{
	struct inode *inode;
	int err;

	if (dentry->d_name.len >= PZXFS_NAME_LEN)
		return -ENAMETOOLONG;

	inode = pzxfs_new_inode(idmap, dir, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	err = pzxfs_add_entry(dir, &dentry->d_name, inode->i_ino);
	if (err) {
		/* 回滚：nlink 归零后 iput 会走 evict_inode 回收块和 inode 号 */
		inode_dec_link_count(inode);
		iput(inode);
		return err;
	}

	d_instantiate(dentry, inode);
	mark_inode_dirty(inode);
	mark_inode_dirty(dir);
	return 0;
}

const struct inode_operations pzxfs_dir_inode_operations = {
	.lookup	= pzxfs_lookup,
	.create	= pzxfs_create,
};

/* ------------------------------------------------------------------ */
/* file_operations（目录）                                             */
/* ------------------------------------------------------------------ */

/*
 * readdir。f_pos（ctx->pos）当作「目录项下标」用，一次遍历整个目录。
 * 不依赖 dcache，所以 umount 后重新 mount，ls 依然能看到磁盘上的文件。
 */
static int pzxfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *dir = file_inode(file);
	struct super_block *sb = dir->i_sb;
	unsigned long nents = dir->i_size / PZXFS_DIRENT_SIZE;
	unsigned long index = ctx->pos;
	struct buffer_head *bh = NULL;
	unsigned long cur_blk = ULONG_MAX;
	int err = 0;

	while (index < nents) {
		unsigned long blk = index / PZXFS_DIRENTS_PER_BLOCK;
		struct pzxfs_dirent *de;
		pzxfs_u32 phys;

		if (blk != cur_blk) {
			brelse(bh);
			bh = NULL;
			cur_blk = blk;

			phys = pzxfs_bmap(dir, blk, 0);
			if (!phys) {
				/* 空洞块，整块跳过 */
				index = (blk + 1) * PZXFS_DIRENTS_PER_BLOCK;
				ctx->pos = index;
				continue;
			}
			bh = sb_bread(sb, phys);
			if (!bh) {
				err = -EIO;
				break;
			}
		}

		de = (struct pzxfs_dirent *)bh->b_data +
		     (index % PZXFS_DIRENTS_PER_BLOCK);

		if (de->inode) {
			ctx->pos = index;
			if (!dir_emit(ctx, de->name,
				      strnlen(de->name, PZXFS_NAME_LEN),
				      de->inode, DT_UNKNOWN))
				break;	/* 用户缓冲区满了，下次从这一项继续 */
		}

		index++;
		ctx->pos = index;
	}

	brelse(bh);
	return err;
}

const struct file_operations pzxfs_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,	/* read() 目录 -> -EISDIR */
	.iterate_shared	= pzxfs_readdir,
};
