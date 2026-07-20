TARGET := armd

DAEMON_DIR := daemon

CORE_OBJS := core/dcontext.o core/dworker.o core/dchannel.o core/dproto.o core/dlog.o
CHNL_OBJS := channel/chnl_calls.o channel/ch_timer.o channel/ch_uevent.o
PROTO_OBJS := proto/proto_calls.o proto/proto_uevent.o
MOD_OBJS := 

OBJS := init/main.o $(CORE_OBJS) $(CHNL_OBJS) $(PROTO_OBJS) $(MOD_OBJS)

CFLAGS += -I./include
LDFLAGS += -lpthread

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sendcmd: debug/sendcmd.o
	$(CC) $(CFLAGS) -o $@ $^

install:
	cp $(TARGET) $(ROOT_DIR)/usr/bin/ -f
#	cp sendcmd $(ROOT_DIR)/usr/bin/ -f

clean:
	rm -f $(TARGET) $(OBJS) debug/sendcmd.o sendcmd
