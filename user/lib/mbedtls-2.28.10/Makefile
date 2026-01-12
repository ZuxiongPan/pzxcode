.PHONY: all clean install

all:
	$(MAKE) -C library SHARED=1

clean:
	$(MAKE) -C library clean

install:
	cp library/libmbedcrypto.so* -af $(ROOT_DIR)/lib64/
