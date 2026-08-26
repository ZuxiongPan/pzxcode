#!/bin/bash

dd if=/dev/zero of=$TOP_DIR/full.bin bs=1K count=256
cat $TOP_DIR/bl1.bin $TOP_DIR/full.bin > $TOP_DIR/bl1_new.bin
dd if=$TOP_DIR/bl1_new.bin of=$TOP_DIR/bl1.bin bs=1K count=256
cat $TOP_DIR/bl1.bin $TOP_DIR/fip.bin > $TOP_DIR/combined.bin
truncate -s 64M $TOP_DIR/combined.bin
