/* SPDX-License-Identifier: GPL-2.0 */
/*
 * pzxfs 磁盘布局定义（内核实现 + 用户态 mkfs 共用）
 *
 * 这个头文件里不允许出现任何内核专有类型，保证 mkfs.pzxfs 在用户态也能编译。
 *
 * 约定：
 *  1. 所有多字节字段都是小端存放。aarch64 / x86 都是小端，所以代码里直接按
 *     主机字节序读写，没有做 cpu_to_le32 转换。要移植到大端平台得补齐转换。
 *  2. 块大小固定 4096 字节。块 N 的字节偏移 = N * 4096，块号从 0 开始。
 *  3. 磁盘布局是编译期固定死的，不做动态探测：
 *
 *        块 0           超级块            struct pzxfs_super_block（只用前 128 字节）
 *        块 1           inode 位图        4096 字节 = 32768 bit，够 512 个 inode
 *        块 2           数据块位图        4096 字节 = 32768 bit，够 128MB 盘
 *        块 3 ~ 18      inode 表          16 块 * 32 个/块 = 512 个 inode，每个 128 字节
 *        块 19          根目录数据块      目录项数组，每项 32 字节
 *        块 20 ~       普通数据块
 */

#ifndef _PZXFS_ONDISK_H
#define _PZXFS_ONDISK_H

#ifdef __KERNEL__
#include <linux/types.h>
typedef __u16 pzxfs_u16;
typedef __u32 pzxfs_u32;
#else
#include <stdint.h>
typedef uint16_t pzxfs_u16;
typedef uint32_t pzxfs_u32;
#endif

/* 0x53465850 按小端写进磁盘后，字节序列正好是 'P' 'X' 'F' 'S' */
#define PZXFS_MAGIC		0x53465850U
#define PZXFS_VERSION		1U

#define PZXFS_BLOCK_SIZE	4096U
#define PZXFS_BLOCK_BITS	12U
#define PZXFS_BLOCK_MASK	(PZXFS_BLOCK_SIZE - 1U)
#define PZXFS_SECTOR_SHIFT	9U	/* 块层以 512 字节为单位 */

/* ---- 固定块号布局 ---- */
#define PZXFS_SB_BLOCK		0U
#define PZXFS_IBITMAP_BLOCK	1U
#define PZXFS_BBITMAP_BLOCK	2U
#define PZXFS_ITABLE_BLOCK	3U

#define PZXFS_MAX_INODES	512U
#define PZXFS_INODE_SIZE	128U
#define PZXFS_INODES_PER_BLOCK	(PZXFS_BLOCK_SIZE / PZXFS_INODE_SIZE)	/* 32 */
#define PZXFS_ITABLE_BLOCKS	(PZXFS_MAX_INODES / PZXFS_INODES_PER_BLOCK) /* 16 */

#define PZXFS_ROOT_BLOCK	(PZXFS_ITABLE_BLOCK + PZXFS_ITABLE_BLOCKS)	/* 19 */
#define PZXFS_FIRST_DATA_BLOCK	(PZXFS_ROOT_BLOCK + 1U)			/* 20 */

#define PZXFS_ROOT_INO		1U

/* inode 里 12 个直接块 + 1 个一级间接块（间接块里放 1024 个块号） */
#define PZXFS_DIRECT_BLOCKS	12U
#define PZXFS_PTRS_PER_BLOCK	(PZXFS_BLOCK_SIZE / 4U)			/* 1024 */
#define PZXFS_MAX_FILESIZE	((PZXFS_DIRECT_BLOCKS + PZXFS_PTRS_PER_BLOCK) * PZXFS_BLOCK_SIZE)

/* 文件名最长 27 个字符 + '\0'，固定长度目录项，够简单 */
#define PZXFS_NAME_LEN		28U
#define PZXFS_DIRENT_SIZE	32U
#define PZXFS_DIRENTS_PER_BLOCK	(PZXFS_BLOCK_SIZE / PZXFS_DIRENT_SIZE)	/* 128 */

/*
 * 超级块，只占块 0 的前 128 字节
 */
struct pzxfs_super_block {
	pzxfs_u32 s_magic;
	pzxfs_u32 s_version;
	pzxfs_u32 s_blocksize;
	pzxfs_u32 s_nblocks;		/* 整盘 4K 块总数 */
	pzxfs_u32 s_ninodes;		/* inode 总数 */
	pzxfs_u32 s_free_blocks;
	pzxfs_u32 s_free_inodes;
	pzxfs_u32 s_root_ino;
	pzxfs_u32 s_ibitmap;		/* inode 位图所在块号 */
	pzxfs_u32 s_bbitmap;		/* 数据块位图所在块号 */
	pzxfs_u32 s_itable;		/* inode 表起始块号 */
	pzxfs_u32 s_itable_blocks;
	pzxfs_u32 s_first_data_block;
	pzxfs_u32 s_mtime;
	char	  s_volume[32];
	pzxfs_u32 s_pad[(128 - 14 * 4 - 32) / 4];	/* 凑满 128 字节 */
};

/*
 * 磁盘 inode，固定 128 字节。i_blocks 记录的是「4K 块个数」，
 * 而 VFS 的 inode->i_blocks 是「512 字节扇区个数」，两边读写时要 <<3 / >>3。
 */
struct pzxfs_inode {
	pzxfs_u16 i_mode;
	pzxfs_u16 i_links_count;
	pzxfs_u32 i_size;
	pzxfs_u32 i_blocks;
	pzxfs_u32 i_mtime;
	pzxfs_u32 i_direct[PZXFS_DIRECT_BLOCKS];
	pzxfs_u32 i_indirect;
	pzxfs_u32 i_reserved[(128 - 2 * 2 - 4 * 3 - 4 * PZXFS_DIRECT_BLOCKS - 4) / 4];
};

/*
 * 目录项，固定 32 字节。inode == 0 表示这个槽位空闲。
 * name 不用记长度，靠 '\0' 结尾即可（所以文件名最长为 NAME_LEN - 1）。
 */
struct pzxfs_dirent {
	pzxfs_u32 inode;
	char	  name[PZXFS_NAME_LEN];
};

_Static_assert(sizeof(struct pzxfs_super_block) == 128, "super_block must be 128 bytes");
_Static_assert(sizeof(struct pzxfs_inode) == PZXFS_INODE_SIZE, "inode must be 128 bytes");
_Static_assert(sizeof(struct pzxfs_dirent) == PZXFS_DIRENT_SIZE, "dirent must be 32 bytes");

#endif /* _PZXFS_ONDISK_H */
