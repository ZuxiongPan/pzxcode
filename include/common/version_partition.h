#ifndef __VERSION_PARTITION_H__
#define __VERSION_PARTITION_H__

#define VERSION_NUMBER "QEMU-Virt-PanZX-V1.0.0"
#define STORDEV_NAME "/dev/sda"
#define STORDEV_PHYSICAL_BLKSIZE 0x200
#define STORDEV_PARTTABLE_SIZE 0x00100000
#define KERNEL_PARTITION_SIZE 0x00800000    // headers + kernel image
#define ROOTFS_PARTITION_SIZE 0x01800000
#define VERSION_PARTITION_SIZE (KERNEL_PARTITION_SIZE + ROOTFS_PARTITION_SIZE)

static const unsigned int AESKEY[8] = {
    0x12121212, 0x34343434, 0x56565656, 0x78787878,
    0x9a9a9a9a, 0xbcbcbcbc, 0xdededede, 0xf0f0f0f0
};
static const unsigned int AESIV[4] = {
    0x12341234, 0x56785678, 0x9abc9abc, 0xdef0def0
};

/** GPT part table
 * block0 protect MBR
 * block1 GPT header
 * block2-block33 main partition table
 * ...
 * last 34 block save backup partitiontable and backup GPT header
*/

// header is at the beginning of the partition
#define SIGNATURE_HEADER_OFFSET 0x0
#define VERSION_HEADER_OFFSET STORDEV_PHYSICAL_BLKSIZE
#define ALL_HEADERS_SIZE (VERSION_HEADER_OFFSET + STORDEV_PHYSICAL_BLKSIZE) // sign header + version header

#define VERSION1_PARTITION_OFFSET STORDEV_PARTTABLE_SIZE
#define VERSION1_PARTITION_SIZE   VERSION_PARTITION_SIZE
#define VERSION1_ROOTFS_PARTITION "/dev/sda2"

#define VERSION2_PARTITION_OFFSET (VERSION1_PARTITION_OFFSET + VERSION1_PARTITION_SIZE)
#define VERSION2_PARTITION_SIZE   VERSION_PARTITION_SIZE
#define VERSION2_ROOTFS_PARTITION "/dev/sda4"

#endif
