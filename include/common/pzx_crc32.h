#ifndef __CRC32_H__
#define __CRC32_H__

#define CRC32_POLYNOMIAL 0xedb88320
#define CRC32_TABLE_SIZE 256

extern unsigned int crc32_table[CRC32_TABLE_SIZE];
/**
 * crc32 table generator

void generate_crc32_table()
{
    unsigned int crc = 0;
    for(int i = 0; i < 256; i++)
    {
        crc = i;
        for(int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
        table[i] = crc;
    }

    return ;
}

*/

unsigned int pzx_crc32(const unsigned char *data, unsigned int length);
unsigned int pzx_crc32_segment(const unsigned char *data, unsigned int length, unsigned int crc);

#endif
