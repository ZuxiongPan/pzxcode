TARGET := versync

CFLAGS += -static

all: $(TARGET)

$(TARGET): versync.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install:
	cp $(TARGET) $(ROOT_DIR)/usr/bin/

clean:
	rm -f $(TARGET)