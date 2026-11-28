// SPDX-License-Identifier: GPL-2.0
/*
 * pzxfs 普通文件的读写
 *
 * 第一版刻意走「手工 read/write」路线（路线 A）：
 *   - 不注册 address_space_operations，也就是完全绕开 page cache；
 *   - 每次 read/write 都自己 sb_bread -> memcpy -> mark_buffer_dirty。
 *
 * 好处是每一次 I/O 都在你眼前，hexdump 能和代码一一对上；
 * 代价是没有预读、没有 mmap、没有共享缓存。
 * 这正是 ext2/bfs 用 block_write_begin 帮你做的事，后面换成路线 B 时
 * 你会立刻看到 page cache 到底替你承担了什么。
 */
#include "pzxfs.h"

static ssize_t pzxfs_read(struct file *filp, char __user *buf, size_t count,
			  loff_t *ppos)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	loff_t pos = *ppos;
	size_t done = 0;

	if (pos < 0)
		return -EINVAL;
	if (pos >= i_size_read(inode))
		return 0;			/* 已到 EOF */

	if (count > i_size_read(inode) - pos)
		count = i_size_read(inode) - pos;	/* 不越过 EOF */
	if (!count)
		return 0;

	while (done < count) {
		loff_t offset_in_file = pos + done;
		unsigned long index = offset_in_file >> PZXFS_BLOCK_BITS;
		size_t offset = offset_in_file & PZXFS_BLOCK_MASK;
		size_t n = min_t(size_t, count - done, PZXFS_BLOCK_SIZE - offset);
		pzxfs_u32 phys = pzxfs_bmap(inode, index, 0);
		struct buffer_head *bh;

		if (!phys) {
			/* 空洞：不读盘，直接给用户态填 0 */
			if (clear_user(buf + done, n))
				return done ? done : -EFAULT;
		} else {
			bh = sb_bread(sb, phys);
			if (!bh)
				return done ? done : -EIO;
			if (copy_to_user(buf + done, bh->b_data + offset, n)) {
				brelse(bh);
				return done ? done : -EFAULT;
			}
			brelse(bh);
		}
		done += n;
	}

	*ppos = pos + done;
	return done;
}

static ssize_t pzxfs_write(struct file *filp, const char __user *buf,
			   size_t count, loff_t *ppos)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	loff_t pos = *ppos;
	size_t done = 0;

	if (pos < 0)
		return -EINVAL;
	if (pos >= PZXFS_MAX_FILESIZE)
		return -EFBIG;
	if (count > PZXFS_MAX_FILESIZE - pos)
		count = PZXFS_MAX_FILESIZE - pos;
	if (!count)
		return -EFBIG;

	while (done < count) {
		loff_t offset_in_file = pos + done;
		unsigned long index = offset_in_file >> PZXFS_BLOCK_BITS;
		size_t offset = offset_in_file & PZXFS_BLOCK_MASK;
		size_t n = min_t(size_t, count - done, PZXFS_BLOCK_SIZE - offset);
		struct buffer_head *bh;
		pzxfs_u32 phys;

		/* create = 1：块不存在就现分配，这就是「数据落到块设备」的起点 */
		phys = pzxfs_bmap(inode, index, 1);
		if (!phys)
			return done ? done : -ENOSPC;

		bh = sb_bread(sb, phys);
		if (!bh)
			return done ? done : -EIO;

		if (copy_from_user(bh->b_data + offset, buf + done, n)) {
			brelse(bh);
			return done ? done : -EFAULT;
		}

		mark_buffer_dirty(bh);
		sync_dirty_buffer(bh);	/* 教学用：立刻落盘，hexdump 马上能看到 */
		brelse(bh);

		done += n;
	}

	if (pos + done > i_size_read(inode))
		i_size_write(inode, pos + done);

	inode_set_mtime_to_ts(inode, current_time(inode));
	*ppos = pos + done;
	mark_inode_dirty(inode);
	return done;
}

/*
 * setattr 只做两件事：截断（O_TRUNC 和 truncate() 都走这里）和
 * 更新 uid/gid/mode/时间戳。没有这个回调，`echo x > file` 会失败，
 * 因为 O_TRUNC 会让 VFS 调 notify_change()。
 */
static int pzxfs_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			 struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int error;

	error = setattr_prepare(idmap, dentry, attr);
	if (error)
		return error;

	if (attr->ia_valid & ATTR_SIZE) {
		if (attr->ia_size > PZXFS_MAX_FILESIZE)
			return -EFBIG;
		/*
		 * pzxfs_truncate() 负责释放块并更新 i_size（两个方向都更新）。
		 * 这里不用 truncate_setsize()：它主要是为了清 page cache，
		 * 而我们根本没有 page cache。
		 */
		pzxfs_truncate(inode, attr->ia_size);
	}

	setattr_copy(idmap, inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

const struct inode_operations pzxfs_file_inode_operations = {
	.setattr	= pzxfs_setattr,
};

/*
 * 只提供 .read / .write（老接口），没有 read_iter：
 * VFS 的 vfs_read/vfs_write 会优先用 .read/.write，
 * 而 new_sync_read 那条适配层根本不会被触发。
 */
const struct file_operations pzxfs_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= pzxfs_read,
	.write		= pzxfs_write,
	/* 每次写都已经 sync_dirty_buffer 落盘了，fsync 没什么可做的 */
	.fsync		= noop_fsync,
};
