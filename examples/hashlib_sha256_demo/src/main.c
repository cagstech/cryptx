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
char hexc[16] = "0123456789ABCDEF";
uint8_t str[] = "The lazy fox jumped over the dog!";

uint8_t sha256_test[] = {0x62,0x82,0xC5,0x63,0x1F,0xC1,0x3E,0x4D,0x70,0x50,0x83,0x15,0xD0,0xF0,0x9B,0xE6,0xD5,0x91,0x52,0xE7,0xB3,0xB9,0x17,0x2B,0xEE,0xFF,0xB3,0x57,0x53,0xE6,0x77,0x9E};

void tohex(char *sbuf, uint8_t *src)
{
	int i;
	int j=0;
	for (i=0; i<SHA256_DIGEST_LEN; i++) {
		sbuf[j++] = hexc[src[i]>>4];
		sbuf[j++] = hexc[src[i]&15];
	}
	sbuf[j] = 0;
}

int main(void)
{
	char *sbuf;
	uint32_t *mbuffer;
    sha256_ctx sha256;
    uint8_t sha256_digest[SHA256_DIGEST_LEN];
    size_t str_len = strlen(str);
	if (!(mbuffer = malloc(64*4))) return 1;
	if (!(sbuf = malloc(SHA256_DIGEST_LEN*2 + 1))) return 1;

	// sprintf(CEMU_CONSOLE, "SHA_CTX Addr: %u\nSHA_CTX EndAddr: %u\n", &sha256, (uint24_t)&sha256 + sizeof(sha256)-1);
    // (*(uint8_t*)-1) = 2;

    sprintf(CEMU_CONSOLE, "The string is '%s'.\n", str);
    sprintf(CEMU_CONSOLE, "Its size is: %u\n", str_len);
    
    hashlib_Sha256Init(&sha256, mbuffer);
    hashlib_Sha256Update(&sha256, str, str_len);
    hashlib_Sha256Final(&sha256, sha256_digest);

	tohex(sbuf, sha256_test);
	sprintf(CEMU_CONSOLE, "Expected hash:  %s \n", sbuf);

	tohex(sbuf, sha256_digest);
	sprintf(CEMU_CONSOLE, "Resulting hash: %s \n", sbuf);

	if(!memcmp(sha256_digest, sha256_test, SHA256_DIGEST_LEN))
        strcpy(CEMU_CONSOLE, "SHA-256 match");
    else strcpy(CEMU_CONSOLE, "SHA-256 did not match");
    strcpy(CEMU_CONSOLE, "\n");
}
