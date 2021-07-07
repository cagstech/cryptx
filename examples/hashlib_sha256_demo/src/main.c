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

#define CEMU_CONSOLE ((char*)0xFB0000)
uint8_t str[] = "The lazy fox jumped over the dog!";

uint8_t sha256_test[] = {0x62,0x82,0xC5,0x63,0x1F,0xC1,0x3E,0x4D,0x70,0x50,0x83,0x15,0xD0,0xF0,0x9B,0xE6,0xD5,0x91,0x52,0xE7,0xB3,0xB9,0x17,0x2B,0xEE,0xFF,0xB3,0x57,0x53,0xE6,0x77,0x9E};
int main(void)
{
	uint32_t mbuffer[80];
    sha256_ctx sha256;
    uint8_t sha256_digest[SHA256_DIGEST_LEN];
    size_t str_len = strlen(str);
    
    sprintf(CEMU_CONSOLE, "The string is '%s'.\n", str);
    sprintf(CEMU_CONSOLE, "Its size is: %u\n", str_len);
    
    hashlib_Sha256Init(&sha256, &mbuffer);
    hashlib_Sha256Update(&sha256, str, str_len);
    hashlib_Sha256Final(&sha256, sha256_digest);
     if(!memcmp(sha256_digest, sha256_test, SHA256_DIGEST_LEN))
        strcpy(CEMU_CONSOLE, "SHA-256 match");
    else strcpy(CEMU_CONSOLE, "SHA-256 did not match");
    strcpy(CEMU_CONSOLE, "\n");
}
