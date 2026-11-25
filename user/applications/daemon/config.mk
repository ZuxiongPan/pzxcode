include compile_cfg

DAEMON_DIR := .
CORE_DIR := core
CHANNEL_DIR := channel
DISPATCHER_DIR := dispatcher
INIT_DIR := init
LIB_DIR := lib
MODULE_DIR := module
VIRTBD_DIR := virt_bd

# Object lists
obj-y :=

obj-y += $(CHANNEL_DIR)/ch_signal.o
obj-y += $(CHANNEL_DIR)/ch_timer.o
obj-y += $(CHANNEL_DIR)/ch_uds.o
obj-y += $(CHANNEL_DIR)/ch_uevent.o

obj-y += $(CORE_DIR)/dchannel.o
obj-y += $(CORE_DIR)/dcontext.o
obj-y += $(CORE_DIR)/dworker.o
obj-y += $(CORE_DIR)/dsync.o

obj-y += $(DISPATCHER_DIR)/dispatcher.o
obj-y += $(DISPATCHER_DIR)/proto_netlink.o
obj-y += $(DISPATCHER_DIR)/proto_socket.o

obj-y += $(INIT_DIR)/fix_comp.o
obj-y += $(INIT_DIR)/main.o

obj-y += $(LIB_DIR)/cJSON.o
obj-y += $(LIB_DIR)/util.o

obj-y += $(MODULE_DIR)/mod_signal.o

# code for qemu-virt board
obj-$(QEMU_VIRT) += $(VIRTBD_DIR)/mod_upgrade.o

# selected objects
obj-$(CONFIG_GENERIC_NETLINK) += $(CHANNEL_DIR)/ch_genl.o

ccflags-y :=

# guard for only one instance of each object
uniq = $(if $1,$(firstword $1) $(call uniq,$(filter-out $(firstword $1),$1)))
OBJS-y := $(call uniq,$(obj-y))
