COMPILER_DIR ?= /home/pzx/aarch64/aarch64-none-linux-gnu-14.3/bin
CC = $(COMPILER_DIR)/aarch64-none-linux-gnu-gcc
OBJCOPY = $(COMPILER_DIR)/aarch64-none-linux-gnu-objcopy

CFLAGS = -Wall -Wextra -O2 -nostdlib -ffreestanding -mcpu=cortex-a53
LDFLAGS = -T linker.ld

.PHONY: all clean

all: loader.img

loader.o: loader.S
	$(CC) $(CFLAGS) -c -o $@ $<

main.o: main.c
	$(CC) $(CFLAGS) -c -o $@ $<

loader.elf: loader.o main.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

loader.img: loader.elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f *.o *.elf *.img

