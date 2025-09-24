#!/bin/bash

cd $ROOT_DIR
make rootfsimg
cd -

dd if=/dev/zero of=$TOP_DIR/version.bin bs=1M count=64

# if nand flash as storage device, need preventing bad block
sfdisk -X gpt $TOP_DIR/version.bin << EOF
1M,8M,L
9M,16M,L
25M,8M,L
33M,16M,L
49M,14M,L
EOF

$CODE_DIR/user/buildversion/buildversion \
    -k $KERNEL_DIR/arch/arm64/boot/Image.gz \
    -r $TOP_DIR/rootfs.img \
    -v $TOP_DIR/version.bin \
    -u $TOP_DIR/upgrade.bin
