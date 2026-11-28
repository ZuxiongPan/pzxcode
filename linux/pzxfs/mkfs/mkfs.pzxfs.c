// SPDX-License-Identifier: GPL-2.0
/*
 * mkfs.pzxfs —— pzxfs 的用户态格式化工具
 *
 * 用法：
 *   ./mkfs.pzxfs /dev/memblk            # 按设备大小格式化
 *   ./mkfs.pzxfs ./memblk.img 2048      # 对普通文件格式化，指定块数
 *
 * 做的事情和内核里的 pzxfs_format() 完全一样（布局见 pzxfs_ondisk.h），
 * 只是内核版用 buffer_head，这里用 pwrite。两边必须保持一致。
 *
 * 你可以拿它先在宿主机上生成一个 8MB 的 memblk.img，然后用
 *   hexdump -C memblk.img | head -40
 * 把整个磁盘布局看一遍，再进虚机操作，理解会快很多。
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "pzxfs_ondisk.h"

#ifndef BLKGETSIZE64
#define BLKGETSIZE64 _IOR(0x12, 114, size_t)
#endif

static int write_block(int fd, unsigned long block, const void *data, size_t len)
{
	off_t off = (off_t)block * PZXFS_BLOCK_SIZE;
	ssize_t n;

	n = pwrite(fd, data, len, off);
	if (n != (ssize_t)len) {
		fprintf(stderr, "写块 %lu 失败: %s\n", block,
			n < 0 ? strerror(errno) : "短写");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	static unsigned char block[PZXFS_BLOCK_SIZE];
	struct pzxfs_super_block *sb;
	struct pzxfs_inode *di;
	struct pzxfs_dirent *de;
	struct stat st;
	unsigned long nblocks, blk;
	unsigned long long bytes;
	const char *path;
	int fd, i;

	if (argc < 2) {
		fprintf(stderr, "用法: %s <设备|镜像文件> [块数]\n", argv[0]);
		return 1;
	}
	path = argv[1];

	fd = open(path, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "打开 %s 失败: %s\n", path, strerror(errno));
		return 1;
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		return 1;
	}

	if (S_ISBLK(st.st_mode)) {
		if (ioctl(fd, BLKGETSIZE64, &bytes) < 0) {
			perror("BLKGETSIZE64");
			return 1;
		}
	} else {
		bytes = (unsigned long long)st.st_size;
	}

	nblocks = (unsigned long)(bytes / PZXFS_BLOCK_SIZE);
	if (argc >= 3)
		nblocks = strtoul(argv[2], NULL, 0);

	if (nblocks > 32768UL)
		nblocks = 32768UL;	/* 位图只有一个块 */
	if (nblocks < PZXFS_FIRST_DATA_BLOCK + 8) {
		fprintf(stderr, "设备太小：%lu 个 4K 块，至少要 %u 个\n",
			nblocks, PZXFS_FIRST_DATA_BLOCK + 8);
		return 1;
	}

	printf("格式化 %s\n", path);
	printf("  总块数      : %lu （每块 %u 字节，共 %lu 字节）\n",
	       nblocks, PZXFS_BLOCK_SIZE, nblocks * PZXFS_BLOCK_SIZE);
	printf("  超级块      : 块 %u\n", PZXFS_SB_BLOCK);
	printf("  inode 位图  : 块 %u\n", PZXFS_IBITMAP_BLOCK);
	printf("  数据块位图  : 块 %u\n", PZXFS_BBITMAP_BLOCK);
	printf("  inode 表    : 块 %u ~ %u （%u 个 inode）\n",
	       PZXFS_ITABLE_BLOCK, PZXFS_ITABLE_BLOCK + PZXFS_ITABLE_BLOCKS - 1,
	       PZXFS_MAX_INODES);
	printf("  根目录块    : 块 %u\n", PZXFS_ROOT_BLOCK);
	printf("  数据区      : 块 %u ~ %lu （%lu 块）\n\n",
	       PZXFS_FIRST_DATA_BLOCK, nblocks - 1,
	       nblocks - PZXFS_FIRST_DATA_BLOCK);

	/* 1. 超级块 */
	memset(block, 0, sizeof(block));
	sb = (struct pzxfs_super_block *)block;
	sb->s_magic		= PZXFS_MAGIC;
	sb->s_version		= PZXFS_VERSION;
	sb->s_blocksize		= PZXFS_BLOCK_SIZE;
	sb->s_nblocks		= nblocks;
	sb->s_ninodes		= PZXFS_MAX_INODES;
	sb->s_free_blocks	= nblocks - PZXFS_FIRST_DATA_BLOCK;
	sb->s_free_inodes	= PZXFS_MAX_INODES - 1;
	sb->s_root_ino		= PZXFS_ROOT_INO;
	sb->s_ibitmap		= PZXFS_IBITMAP_BLOCK;
	sb->s_bbitmap		= PZXFS_BBITMAP_BLOCK;
	sb->s_itable		= PZXFS_ITABLE_BLOCK;
	sb->s_itable_blocks	= PZXFS_ITABLE_BLOCKS;
	sb->s_first_data_block	= PZXFS_FIRST_DATA_BLOCK;
	sb->s_mtime		= (pzxfs_u32)time(NULL);
	memcpy(sb->s_volume, "pzxfs", 6);
	if (write_block(fd, PZXFS_SB_BLOCK, block, sizeof(block)) < 0)
		return 1;

	/* 2. inode 位图：bit0 = 根 inode */
	memset(block, 0, sizeof(block));
	block[0] = 0x01;
	if (write_block(fd, PZXFS_IBITMAP_BLOCK, block, sizeof(block)) < 0)
		return 1;

	/* 3. 数据块位图：0 ~ FIRST_DATA_BLOCK-1 全部置 1 */
	memset(block, 0, sizeof(block));
	for (blk = 0; blk < PZXFS_FIRST_DATA_BLOCK; blk++)
		block[blk / 8] |= 1 << (blk % 8);
	if (write_block(fd, PZXFS_BBITMAP_BLOCK, block, sizeof(block)) < 0)
		return 1;

	/* 4. inode 表全部清零 */
	memset(block, 0, sizeof(block));
	for (blk = PZXFS_ITABLE_BLOCK;
	     blk < PZXFS_ITABLE_BLOCK + PZXFS_ITABLE_BLOCKS; blk++) {
		if (write_block(fd, blk, block, sizeof(block)) < 0)
			return 1;
	}

	/* 5. 根 inode（inode 1，位于 inode 表第一块的第 0 槽） */
	di = (struct pzxfs_inode *)block;
	di->i_mode	  = S_IFDIR | 0755;
	di->i_links_count = 2;
	di->i_size	  = PZXFS_BLOCK_SIZE;
	di->i_blocks	  = 1;
	di->i_mtime	  = (pzxfs_u32)time(NULL);
	di->i_direct[0]	  = PZXFS_ROOT_BLOCK;
	if (write_block(fd, PZXFS_ITABLE_BLOCK, block, sizeof(block)) < 0)
		return 1;

	/* 6. 根目录块： "." 和 ".." */
	memset(block, 0, sizeof(block));
	de = (struct pzxfs_dirent *)block;
	de[0].inode = PZXFS_ROOT_INO;
	strcpy(de[0].name, ".");
	de[1].inode = PZXFS_ROOT_INO;
	strcpy(de[1].name, "..");
	if (write_block(fd, PZXFS_ROOT_BLOCK, block, sizeof(block)) < 0)
		return 1;

	/* 7. 回读校验 */
	if (pread(fd, block, sizeof(block), 0) != (ssize_t)sizeof(block)) {
		perror("回读超级块");
		return 1;
	}
	sb = (struct pzxfs_super_block *)block;
	if (sb->s_magic != PZXFS_MAGIC) {
		fprintf(stderr, "回读校验失败：magic = 0x%08x\n", sb->s_magic);
		return 1;
	}

	printf("完成。超级块 magic = 0x%08x（磁盘字节序列 ", sb->s_magic);
	for (i = 0; i < 4; i++)
		printf("%c", block[i]);
	printf("）\n");
	close(fd);
	return 0;
}
