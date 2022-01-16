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
uint8_t* str = "testing12345";
uint8_t* keystr = "testpass1";

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
	uint32_t mbuffer[64];
    hmac_ctx hmac;
    uint8_t sha256_digest[SHA256_DIGEST_LEN];
    size_t str_len = strlen(str);
	if (!(sbuf = malloc(SHA256_DIGEST_LEN*2 + 1))) return 1;

	// sprintf(CEMU_CONSOLE, "SHA_CTX Addr: %u\nSHA_CTX EndAddr: %u\n", &sha256, (uint24_t)&sha256 + sizeof(sha256)-1);
    // (*(uint8_t*)-1) = 2;

    sprintf(CEMU_CONSOLE, "The string is '%s'.\n", str);
    sprintf(CEMU_CONSOLE, "Its size is: %u\n", str_len);
    sprintf(CEMU_CONSOLE, "After HMAC is: %u\n", ((size_t)&hmac + sizeof(hmac)));
    * ((uint8_t*)0xFFFFFF) = 2;
    hashlib_HMACSha256Init(&hmac, keystr, strlen(keystr));
    hashlib_HMACSha256Update(&hmac, str, strlen(str));
    hashlib_HMACSha256Final(&hmac, sha256_digest);

	tohex(sbuf, sha256_digest);
	sprintf(CEMU_CONSOLE, "Resulting hash: %s \n", sbuf);
    strcpy(CEMU_CONSOLE, "\n");
}
