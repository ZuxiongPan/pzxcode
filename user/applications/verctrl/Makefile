TARGET := verctrl

OPENSSL_DIR := $(CODE_DIR)/user/lib/openssl-3.5.8
CURL_DIR := $(CODE_DIR)/user/lib/curl-8.22.0

CFLAGS += -I$(CODE_DIR)/include
CFLAGS += -I$(OPENSSL_DIR)/include
CFLAGS += -I$(CURL_DIR)/include
LDFLAGS += -L$(OPENSSL_DIR)/lib -lcrypto -lssl
LDFLAGS += -L$(CURL_DIR)/lib -lcurl

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