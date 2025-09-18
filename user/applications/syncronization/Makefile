TARGET := versync

CFLAGS +=

all: $(TARGET)

$(TARGET): versync.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install:
	cp $(TARGET) $(ROOT_DIR)/usr/bin/

clean:
	rm -f $(TARGET)