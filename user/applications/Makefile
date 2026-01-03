CC := $(CROSS_COMPILER_PREFIX)gcc
CFLAGS := -Wall -Wextra -O2
LDFLAGS := 

export CC CFLAGS LDFLAGS

dirs-y :=

dirs-y += uevent_receiver/
dirs-y += eduapp/

.PHONY: all install clean

all:
	for dir in $(dirs-y); do \
		make -C $$dir; \
	done

install:
	for dir in $(dirs-y); do \
		make -C $$dir install; \
	done

clean:
	for dir in $(dirs-y); do \
		make -C $$dir clean; \
	done