TARGET := verctrl

MBEDTLS_DIR := $(CODE_DIR)/user/lib/mbedtls-2.28.10

CFLAGS += -I$(CODE_DIR)/include
CFLAGS += -I$(MBEDTLS_DIR)/include
LDFLAGS += -L$(MBEDTLS_DIR)/library -lmbedcrypto

OBJS := $(patsubst %.c, %.o, $(wildcard *.c))

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

install:
	cp $(TARGET) $(ROOT_DIR)/usr/bin/ -f

clean:
	rm -f $(TARGET) $(OBJS)