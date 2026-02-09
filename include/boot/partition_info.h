#ifndef __PARTITION_INFO__
#define __PARTITION_INFO__

struct simple_part_info {
    char name[32];
    uint32_t size;
    uint32_t start;
};

#define MEGABYTES 0x100000

// this table is only for init, some partitions will be modified
// the first 4 parts cannot change name
static struct simple_part_info simple_partitions[] = 
{
    {
        .name = "kernel0",
        .size = KERNEL_PARTITION_SIZE / MEGABYTES,
        .start = VERSION0_PARTITION_OFFSET / MEGABYTES
    },
    {
        .name = "rootfs0",
        .size = ROOTFS_PARTITION_SIZE / MEGABYTES,
        .start = (VERSION0_PARTITION_OFFSET + KERNEL_PARTITION_SIZE) / MEGABYTES
    },
    {
        .name = "kernel1",
        .size = KERNEL_PARTITION_SIZE / MEGABYTES,
        .start = VERSION1_PARTITION_OFFSET / MEGABYTES
    },
    {
        .name = "rootfs1",
        .size = ROOTFS_PARTITION_SIZE / MEGABYTES,
        .start = (VERSION1_PARTITION_OFFSET + KERNEL_PARTITION_SIZE) / MEGABYTES
    },
    {
        .name = "remainder",
        .size = 0 ,
        .start = (VERSION1_PARTITION_OFFSET + VERSION1_PARTITION_SIZE) / MEGABYTES
    },  // last partition
};

const int part_nums = sizeof(simple_partitions)/sizeof(simple_partitions[0]);

#endif