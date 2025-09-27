#!/bin/bash

cd $ROOT_DIR
make rootfsimg
cd -

dd if=/dev/zero of=$TOP_DIR/version.bin bs=1M count=128

# if nand flash as storage device, need preventing bad block
sfdisk -X gpt $TOP_DIR/version.bin << EOF
1M,8M,L
9M,24M,L
33M,8M,L
41M,24M,L
65M,60M,L
EOF

$CODE_DIR/user/buildversion/buildversion \
    -k $KERNEL_DIR/arch/arm64/boot/Image.gz \
    -r $TOP_DIR/rootfs.img \
    -v $TOP_DIR/version.bin \
    -u $TOP_DIR/upgrade.bin
