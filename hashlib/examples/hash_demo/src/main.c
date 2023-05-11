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
#include <tice.h>
#include <hashlib.h>

#define CEMU_CONSOLE ((char*)0xFB0000)
uint8_t str[] = "The daring fox jumped over the rabid kitten and is sleeping inside.";
#define dbg_Debugger() \
    *(volatile unsigned char*)0xFFFFE0 = (unsigned char)~0
#define HEXDUMP_LINE_LEN	16

void hexdump(uint8_t *addr, size_t len, uint8_t *label){
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
    size_t str_len = strlen(str);
    struct cryptx_hash_ctx ctx;
    uint8_t sha256_digest[CRYPTX_SHA256_DIGEST_LEN];
	uint8_t sha256_hex[(CRYPTX_SHA256_DIGEST_LEN<<1)+1] = {0};
    
    if(!cryptx_hash_init(&ctx, SHA256_HW)) return 1;
    cryptx_hash_update(&ctx, str, str_len);
    cryptx_hash_final(&ctx, sha256_digest);
   
    cryptx_digest_tostring(sha256_digest, sizeof sha256_digest, sha256_hex);
	os_ClrHome();
	os_SetCursorPos(0,0);
	sprintf(CEMU_CONSOLE, "HASHLIB SHA-256 DEMO\nSHA-256: %s\n", sha256_hex);
    //strcpy(CEMU_CONSOLE, sha256_hex);
    //strcpy(CEMU_CONSOLE, "\n");
    return 0;
}
