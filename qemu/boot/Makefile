COMPILER_DIR = /home/pzx/study/aarch64-none-linux-gnu-14.3/bin
CC = $(COMPILER_DIR)/aarch64-none-linux-gnu-gcc
OBJCOPY = $(COMPILER_DIR)/aarch64-none-linux-gnu-objcopy

CFLAGS = -Wall -Wextra -O2 -nostdlib -ffreestanding -mcpu=cortex-a53
LDFLAGS = -T linker.ld

.PHONY: all clean bootcode

all: bootcode

startup.o: startup.S
	$(CC) $(CFLAGS) -c -o $@ $<

main.o: main.c
	$(CC) $(CFLAGS) -c -o $@ $<

boot.elf: startup.o main.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

boot.img: boot.elf
	$(OBJCOPY) -O binary $< $@

bootcode: boot.img
	xxd -i boot.img | sed 's/boot_img/bootcode/g'

clean:
	rm -f *.o *.elf *.img

