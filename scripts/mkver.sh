#!/bin/bash

HEADER_FILE=$CODE_DIR/include/common/version_partition.h
ROOTFS_SIZE_HEX=$(grep -w "ROOTFS_PARTITION_SIZE" $HEADER_FILE | grep "#define" | \
    grep -v "(" | awk '{print $3}')
ROOTFS_BLKSIZE=1024
ROOTFS_BLKCOUNT=$(( ROOTFS_SIZE_HEX / ROOTFS_BLKSIZE / 4 * 3 ))

echo "rootfs block size: $ROOTFS_BLKSIZE"
echo "rootfs block count: $ROOTFS_BLKCOUNT"

export ROOTFS_BLKSIZE ROOTFS_BLKCOUNT

cd $ROOT_DIR
make rootfsimg
cd -

#dd if=/dev/zero of=$TOP_DIR/version.bin bs=1M count=128

$CODE_DIR/host/buildversion/buildversion \
    -k $TOP_DIR/kernel.itb \
    -r $TOP_DIR/rootfs.img \
    -u $TOP_DIR/upgrade.bin \
    -p $CODE_DIR/rsakeys/pzx.key
#    -v $TOP_DIR/version.bin
