CC := gcc

CFLAGS := -Wall -Wextra -O2
CFLAGS += -I../../include

all: buildversion

buildversion: pzx_crc32table.c buildversion.c
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f buildversion