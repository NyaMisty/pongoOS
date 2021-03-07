/* 
 * pongoOS - https://checkra.in
 * 
 * Copyright (C) 2019-2020 checkra1n team
 *
 * This file is part of pongoOS.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */
#ifdef AUTOBOOT
#include <pongo.h>
uint64_t* autoboot_block;

typedef struct {
    uint64_t magic;
    char command[24];
    uint64_t sleeptime;
    uint64_t length;
    void *data;
} autoboot_subblock;

void load_mod(autoboot_subblock *curblock, int stage) {
    if (stage == 1) {
        uint32_t curblock_size = curblock->length;
        iprintf("Loading mod with length %d command %s\n", curblock_size, curblock->command);
        resize_loader_xfer_data(curblock_size);
        //memcpy(loader_xfer_recv_data, &curblock[1], curblock_size);
        memcpy(loader_xfer_recv_data, curblock->data, curblock_size);
        loader_xfer_recv_count = curblock_size;
        free(curblock->data);
        curblock->data = NULL;

        queue_rx_string("modload\n");
        int sleeptime = curblock->sleeptime / 3;
        if (sleeptime < 400 * 1000) {
            sleeptime = 400 * 1000;
        }
        usleep(sleeptime);
    } else {
        char curblock_command[25];
        memcpy(curblock_command, &curblock->command, 24);
        curblock_command[24] = 0;
        int command_len = strlen(curblock_command);

        if (command_len > 0) {
            curblock_command[command_len] = '\n';
            curblock_command[command_len+1] = '\0';
            queue_rx_string(curblock_command);
            usleep(curblock->sleeptime / 3 * 2);
        }
    }
}

void do_autoboot() {
    if (autoboot_block) {
        autoboot_subblock Mods[16] = { 0 };
        int modNum = 0;

        uint32_t total_len = (uint32_t)autoboot_block[1];
        autoboot_count = total_len;
        uint32_t cur_offset = 0;
        while (cur_offset * 8 < total_len) {
            autoboot_subblock *curblock = (autoboot_subblock *)(&autoboot_block[2] + cur_offset);

            cur_offset += (sizeof(autoboot_subblock) - sizeof(curblock->data)) >> 3;
            if (curblock->magic != 0x646f6d626f747561) {
                iprintf("Got wrong sub autoboot block header: %lld\n", curblock->magic);
                return;
            }
            uint32_t curblock_size = (uint32_t)curblock->length;
            if (curblock_size == 0xffffffff) {
                curblock_size = curblock->length = autoboot_count - cur_offset * 8;
            } else if (curblock_size & 7 || curblock_size + cur_offset * 8 > total_len) {
                iprintf("Got invalid mod block size: %lld\n", curblock->length);
                return;
            }
            cur_offset += (curblock_size >> 3);

            char curblock_command[25];
            memcpy(curblock_command, &curblock->command, 24);
            curblock_command[24] = 0;
            int command_len = strlen(curblock_command);
            if (command_len >= 24) {
                iprintf("Got too long command: %s\n", curblock_command);
                return;
            }

            //pMods[modNum] = curblock;
            memcpy(&Mods[modNum], curblock, sizeof(autoboot_subblock));
            Mods[modNum].data = malloc(curblock_size);
            memcpy(Mods[modNum].data, &curblock->data, curblock_size);
            modNum++;
        }
        
        for (int i = modNum - 1; i >= 0; i--) {
            load_mod(&Mods[i], 1);
            queue_rx_string("autoboot\n");
            usleep(300 * 1000);
            command_unregister("autoboot");
        }

        for (int i = 0; i < modNum; i++) {
        //for (int i = modNum - 1; i >= 0; i--) {
            load_mod(&Mods[i], 2);
        }
	}
}

void pongo_autoboot()
{
    do_autoboot();
    if (autoboot_block) {
        phys_force_free(vatophys((uint64_t)autoboot_block), (autoboot_block[1] + 0x20 + 0x3fff) & ~0x3fff);
    }
}

#endif
