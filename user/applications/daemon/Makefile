TARGET := armd

DAEMON_DIR := daemon

CORE_OBJS := core/bus.o core/evloop.o core/module.o core/worker.o
CHNL_OBJS := channel/timer.o channel/uevent.o channel/server.o channel/client.o channel/uds.o channel/parser.o
PROTO_OBJS := protocol/uevent_proto.o protocol/uds_proto.o
MOD_OBJS := 

OBJS := init/main.o $(CORE_OBJS) $(CHNL_OBJS) $(PROTO_OBJS) $(MOD_OBJS)

CFLAGS += -I./include
LDFLAGS += -lpthread

all: $(TARGET) sendcmd

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

sendcmd: debug/sendcmd.o
	$(CC) $(CFLAGS) -o $@ $^

install:
	cp $(TARGET) $(ROOT_DIR)/usr/bin/ -f
	cp sendcmd $(ROOT_DIR)/usr/bin/ -f

clean:
	rm -f $(TARGET) $(OBJS) debug/sendcmd.o sendcmd
