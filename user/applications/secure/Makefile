TARGET := secure

CFLAGS +=

all: $(TARGET)

$(TARGET): secure.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install:
	cp $(TARGET) $(ROOT_DIR)/usr/bin/

clean:
	rm -f $(TARGET)