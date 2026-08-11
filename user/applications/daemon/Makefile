TARGET := armd

DAEMON_DIR := daemon

CORE_OBJS := core/dcontext.o core/dworker.o core/dchannel.o core/dproto.o core/dmodule.o
CHNL_OBJS := channel/chnl_calls.o channel/ch_timer.o channel/ch_uevent.o channel/ch_uds.o
PROTO_OBJS := proto/proto_calls.o proto/proto_uevent.o proto/proto_json.o
MOD_OBJS := module/mod_calls.o module/mod_block.o module/mod_status.o \
		module/mod_upgrade.o
LIB_OBJS := lib/cJSON.o

OBJS := init/main.o $(CORE_OBJS) $(CHNL_OBJS) $(PROTO_OBJS) $(MOD_OBJS) $(LIB_OBJS)

CFLAGS += -I./include -I./
LDFLAGS += -lpthread

all: $(TARGET) sendcmd

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sendcmd: debug/sendcmd.o lib/cJSON.o
	$(CC) $(CFLAGS) -o $@ $^

install:
	cp $(TARGET) $(ROOT_DIR)/usr/bin/ -f
	cp sendcmd $(ROOT_DIR)/usr/bin/ -f

clean:
	rm -f $(TARGET) $(OBJS) debug/sendcmd.o sendcmd
