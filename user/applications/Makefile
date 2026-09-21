CC := $(CROSS_COMPILER_PREFIX)gcc
CFLAGS := -Wall -Wextra -O2
LDFLAGS := 

export CC CFLAGS LDFLAGS

dirs-y :=

dirs-y += daemon/
dirs-y += verctrl/
#dirs-y += eduapp/
#dirs-y += uevent_receiver/

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