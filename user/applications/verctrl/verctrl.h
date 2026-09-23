#ifndef __VERCTRL_H__
#define __VERCTRL_H__

#include "common/data_type.h"

enum upgrade_stage {
    UPG_DOWNLOADING = 0,
    UPG_DOWNLOAD_FAILED,
    UPG_DOWNLOADED,
    UPG_BEGIN,
    UPG_CHECKING,
    UPG_CHECK_FAILED,
    UPG_CHECKED,
    UPG_WRITING,
    UPG_WRITE_FAILED,
    UPG_WRITTEN,
    UPG_SUCCESS,
    UPG_END,
};

#define UPGRADE_FILE_PATH "tftp://10.0.2.2/upgrade.bin"
#define DOWNLOAD_FILE_PATH "/var/fw.bin"
#define UDS_PATH "/var/armd.sock"
#define PUBKEY_FILEPATH "/etc/pzx.pub"
#define UPG_MSG_MAXLEN 128
#define CONFIG_UPGRADE_FRAGMENT
#define FRAGMENT_SIZE 0x100000

int init_uds_socket(void);
int inform_to_armd(enum upgrade_stage stage);
void cleanup_uds_socket(void);
const char *get_upgrade_stage_str(enum upgrade_stage stage);

int download_upgrade_file(void);

int version_sync(void);
int write_upgrade_file(char *upgfile_name);

int get_value_from_verinfo(const char *name, char *valbuf, unsigned int bufsize);
int aes256_cbc_decrypt(uint8_t *data, unsigned int datalen, uint8_t *iv);

uint32_t pzx_crc32(const uint8_t *data, uint32_t length);
uint32_t pzx_crc32_segment(const uint8_t *data, uint32_t length, uint32_t crc);

#endif