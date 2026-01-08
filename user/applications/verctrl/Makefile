TARGET := verctrl

CFLAGS += -I$(CODE_DIR)/include

OBJS := $(patsubst %.c, %.o, $(wildcard *.c))

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $@ $<

install:
	cp $(TARGET) $(ROOT_DIR)/usr/bin/ -f

clean:
	rm -f $(TARGET) $(OBJS)