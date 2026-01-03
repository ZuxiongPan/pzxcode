CC := gcc

CFLAGS := -Wall -Wextra -O2
CFLAGS += -I../../include -lcrypto -lssl

SRCS := $(wildcard *.c)

all: buildversion

buildversion: $(SRCS)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f buildversion