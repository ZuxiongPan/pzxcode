include config.mk

TARGET := armd

define add_dir_objs
OBJS-y += $(patsubst $(1)/%.c, $(1)/%.o, $(wildcard $(1)/*.c))
endef

$(foreach dir, $(DIRS-y), $(eval $(call add_dir_objs,$(dir))))
$(foreach dir, $(MOD_SUBDIRS-y), $(eval $(call add_dir_objs,$(dir))))

CFLAGS += -I$(DAEMON_DIR)/include -I$(DAEMON_DIR)
LDFLAGS += -lpthread

all: $(TARGET) sendcmd

$(TARGET): $(OBJS-y)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	$(CROSS_COMPILER_PREFIX)strip $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

sendcmd: debug/sendcmd.o lib/cJSON.o
	$(CC) $(CFLAGS) -o $@ $^

install:
	cp $(TARGET) $(ROOT_DIR)/usr/bin/ -f
	cp sendcmd $(ROOT_DIR)/usr/bin/ -f

clean:
	rm -f $(TARGET) $(OBJS-y) debug/sendcmd.o sendcmd