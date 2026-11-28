/* SPDX-License-Identifier: GPL-2.0 */
/*
 * pzxfs 内核侧数据结构与函数声明
 */
#ifndef _PZXFS_H
#define _PZXFS_H

#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/bitmap.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/timekeeping.h>
#include <linux/statfs.h>

#include "pzxfs_ondisk.h"

/*
 * 常驻内存的 inode 私有数据。
 * 块指针是 inode 级的状态（不像 i_size 那样 VFS 已经帮我们存了），
 * 所以必须自己存一份，读写时不用每次都去 sb_bread 磁盘 inode。
 */
struct pzxfs_inode_info {
	pzxfs_u32		i_direct[PZXFS_DIRECT_BLOCKS];
	pzxfs_u32		i_indirect;
	struct inode		vfs_inode;
};

/* 常驻内存的超级块私有数据（挂载时从磁盘超级块读出来） */
struct pzxfs_sb_info {
	unsigned long	s_nblocks;
	unsigned long	s_ninodes;
	unsigned long	s_free_blocks;
	unsigned long	s_free_inodes;
	unsigned long	s_ibitmap_hint;	/* 下次分配从哪找起，避免每次从头扫 */
	unsigned long	s_bbitmap_hint;
	pzxfs_u32	s_ibitmap;
	pzxfs_u32	s_bbitmap;
	pzxfs_u32	s_itable;
	pzxfs_u32	s_first_data_block;
};

/* 挂载参数，只认 -o format */
struct pzxfs_fs_context {
	bool		format;
};

#define PZXFS_SB(sb)	((struct pzxfs_sb_info *)((sb)->s_fs_info))
#define PZXFS_I(inode)	container_of(inode, struct pzxfs_inode_info, vfs_inode)

/* super.c */
extern const struct super_operations pzxfs_sops;
int pzxfs_init_inode_cache(void);

/* inode.c */
struct inode *pzxfs_iget(struct super_block *sb, unsigned long ino);
struct inode *pzxfs_new_inode(struct mnt_idmap *idmap, struct inode *dir, umode_t mode);
void pzxfs_free_inode(struct inode *inode);
int pzxfs_write_inode(struct inode *inode, struct writeback_control *wbc);
void pzxfs_evict_inode(struct inode *inode);
struct inode *pzxfs_alloc_inode(struct super_block *sb);
void pzxfs_destroy_inode(struct inode *inode);

pzxfs_u32 pzxfs_alloc_block(struct inode *inode, int zero);
void pzxfs_free_block(struct inode *inode, pzxfs_u32 block);
pzxfs_u32 pzxfs_bmap(struct inode *inode, unsigned long block, int create);
void pzxfs_truncate(struct inode *inode, loff_t newsize);

/* namei.c */
extern const struct inode_operations pzxfs_dir_inode_operations;
extern const struct file_operations pzxfs_dir_operations;

/* file.c */
extern const struct inode_operations pzxfs_file_inode_operations;
extern const struct file_operations pzxfs_file_operations;

#endif /* _PZXFS_H */
