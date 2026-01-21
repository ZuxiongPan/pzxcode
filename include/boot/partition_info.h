#ifndef __PARTITION_INFO__
#define __PARTITION_INFO__

struct simple_part_info {
    char name[32];
    uint32_t size;
};

// this table is only for init, some partitions will be modified
// the first 4 parts cannot change name
static struct simple_part_info simple_partitions[] = 
{
    { .name = "kernel0", .size = KERNEL_PARTITION_SIZE / 0x100000 },
    { .name = "rootfs0", .size = ROOTFS_PARTITION_SIZE / 0x100000 },
    { .name = "kernel1", .size = KERNEL_PARTITION_SIZE / 0x100000 },
    { .name = "rootfs1", .size = ROOTFS_PARTITION_SIZE / 0x100000 },
    { .name = "remainder", .size = 0 },  // last partition
};

const int part_nums = sizeof(simple_partitions)/sizeof(simple_partitions[0]);

#endif