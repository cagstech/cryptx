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
#include <encrypt.h>

#define CEMU_CONSOLE ((char*)0xFB0000)
char *str1 = "The lazy fox jumped over the dog!";
char *str2 = "The lazier fox fell down!";
#define KEYSIZE (256>>3)    // 256 bits converted to bytes

// change to #define CBC_MODE to test CBC mode instead
#define CTR_MODE

void hexdump(uint8_t *addr, size_t len, char *label){
    if(label) sprintf(CEMU_CONSOLE, "\n%s\n", label);
    else sprintf(CEMU_CONSOLE, "\n");
    for(size_t rem_len = len, ct=1; rem_len>0; rem_len--, addr++, ct++){
        sprintf(CEMU_CONSOLE, "\\x%02X", *addr);
        if(!(ct%AES_BLOCKSIZE)) sprintf(CEMU_CONSOLE, "\n");
    }
    sprintf(CEMU_CONSOLE, "\n");
}

int main(void)
{
    // reserve key schedule and key buffer, IV.
    aes_ctx ctx;
    aes_error_t error;
    
    size_t msg1_len = strlen(str1);
    size_t msg2_len = strlen(str2);
    uint8_t buf1[256];
    uint8_t buf2[256];
    uint8_t stripped[256];
    
    sprintf(CEMU_CONSOLE, "\n---------------------------\nHASHLIB AES Demo\n");
    sprintf(CEMU_CONSOLE, "\n----- CBC Mode -----\n");
    hexdump(str1, msg1_len, "-- Original String 1 --");
    hexdump(str2, msg2_len, "-- Original String 2 --");
    
    
    // generate random key and IV
    if(!csrand_init(SAMPLING_FAST)) return 1;          // <<<----- DONT FORGET THIS
    // !!!! NEVER PROCEED WITH ANYTHING CRYPTOGRAPHIC !!!!
    // !!!! IF THE CSRNG FAILS TO INIT !!!!
    
    // generate key and IV
    uint8_t key[] = {0xEE,0x89,0x19,0xC3,0x8D,0x53,0x7A,0xD6,0x04,0x19,0x9E,0x77,0x0B,0xE0,0xE0,0x4C,0x4C,0x70,0xDB,0xE1,0x22,0x79,0xE1,0x90,0x06,0x1B,0xAF,0x99,0x49,0x8E,0x66,0x73};
   uint8_t iv[] = {0x79,0xA6,0xDE,0xDF,0xF0,0xA2,0x7C,0x7F,0xEE,0x0B,0x8E,0xF5,0x12,0x63,0xA4,0x8A};
    
    // show the IV and key for testing purposes
    hexdump(key, KEYSIZE, "-- AES secret --");
    hexdump(iv, AES_IVSIZE, "-- initialization vector --");
    
    // initialize the AES key schedule and set cipher mode
    #ifdef CBC_MODE
    error = aes_init(&ctx, key, KEYSIZE, iv, PAD_ISO2);
    #endif
    #ifdef CTR_MODE
	error = aes_init(&ctx, key, KEYSIZE, iv, AES_MODE_CTR);
    #endif
    sprintf(CEMU_CONSOLE, "aes ctx init done, exit code %u\n", error);
    
    // encrypt message 1 and output return code and encrypted data for testing
    error = aes_encrypt(&ctx, str1, msg1_len, buf1);
	sprintf(CEMU_CONSOLE, "message segment 1 done, exit code %u\n", error);
    
    // encrypt message 2 and output return code and encrypted data for testing
    error = aes_encrypt(&ctx, str2, msg2_len, buf2);
    sprintf(CEMU_CONSOLE, "message segment 2 done, exit code %u\n", error);
    
    #ifdef CBC_MODE
    hexdump(buf1, aes_outsize(msg1_len), "-- Encrypted Message 1 --");
    hexdump(buf2, aes_outsize(msg2_len), "-- Encrypted Message 2 --");
    #endif
    #ifdef CTR_MODE
    hexdump(buf1, msg1_len, "-- Encrypted Message 1 --");
    hexdump(buf2, msg2_len, "-- Encrypted Message 2 --");
    #endif
    
    return 0;
    
}
