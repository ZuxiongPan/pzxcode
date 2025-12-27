#!/bin/bash

cd $ROOT_DIR
make rootfsimg
cd -

dd if=/dev/zero of=$TOP_DIR/version.bin bs=1M count=128

$CODE_DIR/user/buildversion/buildversion \
    -k $TOP_DIR/kernel.itb \
    -r $TOP_DIR/rootfs.img \
    -v $TOP_DIR/version.bin \
    -u $TOP_DIR/upgrade.bin
