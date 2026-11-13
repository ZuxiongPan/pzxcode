include compile_cfg

DAEMON_DIR := .
CHANNEL_DIR := $(DAEMON_DIR)/channel
CORE_DIR := $(DAEMON_DIR)/core
DISPATCHER_DIR := $(DAEMON_DIR)/dispatcher
INIT_DIR := $(DAEMON_DIR)/init
LIB_DIR := $(DAEMON_DIR)/lib
MODULE_DIR := $(DAEMON_DIR)/module
UEVENT_DIR := $(DAEMON_DIR)/uevent

DIRS-y := $(CHANNEL_DIR) $(CORE_DIR) $(DISPATCHER_DIR) $(INIT_DIR) $(LIB_DIR) $(MODULE_DIR)

OBJS-y :=
MOD_SUBDIRS-y :=

# compile_cfg still carries the CONFIG_* switches. the lines below used to be
# spelled "DIRS-$(CONFIG_...)", and the Makefile only ever walks DIRS-y, so those
# switches never did anything. gating on the value makes them real.
DIRS-$(CONFIG_MODULE_UEVENT) += $(UEVENT_DIR)

# input/ and module/memblk still use the pre-refactor API (dchannel_t,
# dmodule_register, TASK_DATA_MAXSIZE), so they stay out of the build until they
# are ported to the channel/dispatcher/components structure.
# DIRS-$(CONFIG_INPUT_SUPPORT) += $(DAEMON_DIR)/input
# MOD_SUBDIRS-$(CONFIG_MODULE_MEMBLK) += $(MODULE_DIR)/memblk
