CC := $(CROSS_COMPILER_PREFIX)gcc
CFLAGS := -Wall -Wextra -O2
LDFLAGS := 

export CC CFLAGS LDFLAGS

dirs-y :=

dirs-y += mbedtls-2.28.10/

.PHONY: all install clean

all:
	for dir in $(dirs-y); do \
		$(MAKE) -C $$dir; \
	done

install:
	for dir in $(dirs-y); do \
		$(MAKE) -C $$dir install; \
	done

clean:
	for dir in $(dirs-y); do \
		$(MAKE) -C $$dir clean; \
	done