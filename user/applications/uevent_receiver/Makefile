TARGET := urecv

CFLAGS +=

all: $(TARGET)

$(TARGET): uevent_receiver.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install:
	cp $(TARGET) $(ROOT_DIR)/usr/bin/

clean:
	rm -f $(TARGET)