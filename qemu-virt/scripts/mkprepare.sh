#!/bin/bash

if [ ! -L $KERNEL_DIR/cuskernel ]; then
    echo "need create cuskernel softlink"
    ln -sf $CODE_DIR/linux $KERNEL_DIR/cuskernel
fi

if [ ! -L $UBOOT_DIR/cusuboot ]; then
    echo "need create cusuboot softlink"
    ln -sf $CODE_DIR/uboot $UBOOT_DIR/cusuboot
fi

if [ ! -n "$(ls -A $ROOT_DIR)" ]; then
    echo "need copy basefilesystem"
    mkdir -p $ROOT_DIR/{proc,sys,dev,mnt,lib64,lib,modules,var}
    cp -rf $CODE_DIR/qemu-virt/scripts/baserootfs/* $ROOT_DIR/
fi
