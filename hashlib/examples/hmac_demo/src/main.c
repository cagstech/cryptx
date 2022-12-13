/*
 *--------------------------------------
 * Program Name:
 * Author:
 * License:
 * Description:
 *--------------------------------------
*/

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <hashlib.h>
#include <debug.h>

#define CEMU_CONSOLE ((char*)0xFB0000)
uint8_t* str = "testing12345";
uint8_t* hmac_keystr = "testpass1";
#define HEXDUMP_LINE_LEN	16

void hexdump(uint8_t *addr, size_t len, char *label){
    if(label) sprintf(CEMU_CONSOLE, "\n%s\n", label);
    else sprintf(CEMU_CONSOLE, "\n");
    for(size_t rem_len = len, ct=1; rem_len>0; rem_len--, addr++, ct++){
        sprintf(CEMU_CONSOLE, "%02X ", *addr);
        if(!(ct%HEXDUMP_LINE_LEN)) sprintf(CEMU_CONSOLE, "\n");
    }
    sprintf(CEMU_CONSOLE, "\n");
}

int main(void)
{
    struct cryptx_hmac_ctx hmac;
    uint8_t sha256_digest[CRYPTX_SHA256_DIGEST_LEN];
    if(!cryptx_hmac_init(&hmac, hmac_keystr, strlen(hmac_keystr), SHA256)) return 1;
    cryptx_hmac_update(&hmac, str, strlen(str));
    cryptx_hmac_final(&hmac, sha256_digest);

	hexdump(sha256_digest, sizeof sha256_digest, "-SHA-256 HMAC Output-");
}
