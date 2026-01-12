CC := $(CROSS_COMPILER_PREFIX)gcc
CFLAGS := -Wall -Wextra -O2 -include $(CODE_DIR)/include/pzx_config.h
LDFLAGS := 

export CC CFLAGS LDFLAGS

dirs-y :=

dirs-y += uevent_receiver/
#dirs-y += eduapp/
dirs-y += verctrl/

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