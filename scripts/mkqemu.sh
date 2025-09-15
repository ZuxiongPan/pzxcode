#!/bin/bash
QEMU_BUILD_DIR=$QEMU_DIR/build

cd $QEMU_DIR

echo "Building QEMU..."
./configure \
    --prefix=$QEMU_BUILD_DIR \
    --target-list=aarch64-softmmu
make -j16
make install

echo "Building QEMU Over..."

cd -
