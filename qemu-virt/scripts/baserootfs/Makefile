
initramfs:
	find . -print0 | cpio --null -ov --format=newc | gzip > ../initramfs.cpio.gz

rootfsimg:
	rm -f ../rootfs.img
	mkfs.ext4 -F -b $(ROOTFS_BLKSIZE) -d $(PWD) ../rootfs.img $(ROOTFS_BLKCOUNT)