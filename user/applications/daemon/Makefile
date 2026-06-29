TARGET := armd

DAEMON_DIR := daemon

CORE_OBJS := core/bus.o core/evloop.o core/module.o core/worker.o
EVSRC_OBJS := evsrc/common/timer.o evsrc/common/uevent.o
MOD_OBJS := modules/cpumem.o

OBJS := init/main.o $(CORE_OBJS) $(EVSRC_OBJS) $(MOD_OBJS)

CFLAGS += -I./include
LDFLAGS += -lpthread

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

install:
	cp $(TARGET) $(ROOT_DIR)/usr/bin/ -f

clean:
	rm -f $(TARGET) $(OBJS)
