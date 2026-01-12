CC := gcc

CFLAGS := -Wall -Wextra -O2
CFLAGS += -I$(CODE_DIR)/include -lcrypto -lssl -include $(CODE_DIR)/include/pzx_config.h

SRCS := $(wildcard *.c)

all: buildversion

buildversion: $(SRCS)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm -f buildversion