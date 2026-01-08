TARGET := edu

CFLAGS +=

all: $(TARGET)

$(TARGET): eduapp.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

install:
	cp $(TARGET) $(ROOT_DIR)/usr/bin/ -f

clean:
	rm -f $(TARGET)