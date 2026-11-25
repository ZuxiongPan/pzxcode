include config.mk

TARGET := armd

# sendcmd only rely on following objects
SENDCMD_OBJS := debug/sendcmd.o lib/cJSON.o

CFLAGS += -I$(DAEMON_DIR)/include -I$(DAEMON_DIR) -I$(CODE_DIR)/include
CFLAGS += -MMD -MP
LDFLAGS += -lpthread

DEPS := $(sort $(OBJS-y:.o=.d) $(SENDCMD_OBJS:.o=.d))

all: $(TARGET) sendcmd

$(TARGET): $(OBJS-y)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	$(CROSS_COMPILER_PREFIX)strip $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

sendcmd: $(SENDCMD_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

install:
	cp $(TARGET) $(ROOT_DIR)/usr/bin/ -f
	cp sendcmd $(ROOT_DIR)/usr/bin/ -f

clean:
	rm -f $(TARGET) sendcmd $(OBJS-y) $(SENDCMD_OBJS) $(DEPS)

-include $(DEPS)

.PHONY: all install clean check-obj
check-obj:
	@for f in $$(find . -name '*.c' | sed 's|^\./||' | sort); do \
		o=$${f%.c}.o; \
		case " $(OBJS-y) $(SENDCMD_OBJS) " in \
			*" $$o "*) ;; \
			*) echo "un registered file: $$f" ;; \
		esac; \
	done
