#ifndef _MOD_DATA_
#define _MOD_DATA_

#define BLKDEV_NAME_MAXLEN 32

typedef struct blk_info {
    char blkdev_name[BLKDEV_NAME_MAXLEN];
} blk_info_t;

#endif