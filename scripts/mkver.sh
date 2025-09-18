#!/bin/bash

cd $ROOT_DIR
make rootfsimg
cd -

dd if=/dev/zero of=$TOP_DIR/version.bin bs=1M count=64

sfdisk -X gpt $TOP_DIR/version.bin << EOF
1M,10M,L
11M,20M,L
31M,10M,L
41M,20M,L
EOF

$CODE_DIR/user/buildversion/buildversion \
    -k $KERNEL_DIR/arch/arm64/boot/Image \
    -r $TOP_DIR/rootfs.img \
    -v $TOP_DIR/version.bin \
    -u $TOP_DIR/upgrade.bin
