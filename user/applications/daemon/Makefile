TARGET := armd

DAEMON_DIR := daemon

CORE_OBJS := core/dcontext.o core/dworker.o core/dchannel.o
CHNL_OBJS := channel/ch_timer.o channel/chnl_calls.o
PROTO_OBJS := 
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
