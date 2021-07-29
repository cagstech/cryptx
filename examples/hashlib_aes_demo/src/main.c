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
#define KEYSIZE (256>>3)    // 256 bits
#define IV_LEN  AES_BLOCKSIZE   // defined <hashlib.h>

void hexdump(uint8_t *addr, size_t len, uint8_t *label){
    if(label) sprintf(CEMU_CONSOLE, "\n%s\n", label);
    else sprintf(CEMU_CONSOLE, "\n");
    for(size_t rem_len = len, ct=1; rem_len>0; rem_len--, addr++, ct++){
        sprintf(CEMU_CONSOLE, "%02X ", *addr);
        if(!(ct%AES_BLOCKSIZE)) sprintf(CEMU_CONSOLE, "\n");
    }
    sprintf(CEMU_CONSOLE, "\n");
}

int main(void)
{
    // reserve key schedule and key buffer, IV, and encrypt/decrypt buffers
    aes_ctx ctx;
    uint8_t key[KEYSIZE];
    uint8_t iv[IV_LEN];
    size_t stripped_len;
    
    size_t msg_len = strlen(str);
    size_t padded_len = hashlib_AESPaddedSize(msg_len);
  //  uint8_t *padded = hashlib_AllocContext(padded_len);
    uint8_t *buf = hashlib_AllocContext(padded_len);
   // uint8_t *buf2 = hashlib_AllocContext(padded_len);
    uint8_t *stripped = hashlib_AllocContext(padded_len);
    
    // generate random key and IV
    hashlib_RandomBytes(key, KEYSIZE);
    hashlib_RandomBytes(iv, IV_LEN);
    
    // pad the input message
    hashlib_AESPadMessage(str, msg_len, buf, SCHM_DEFAULT);
    hexdump(buf, padded_len, "-- Padded Message --");
    
    // load the key into the key schedule
    hashlib_AESLoadKey(key, &ctx, (KEYSIZE<<3)); // requires size in bits, not bytes
    
	if(hashlib_AESEncrypt(buf, padded_len, buf, &ctx, iv)) {
		sprintf(CEMU_CONSOLE, "encrypt success\n");
		hexdump(buf, padded_len, "-- Encrypted Message --");
	}
	else sprintf(CEMU_CONSOLE, "encrypt failed\n");
    //hashlib_AESEncryptBlock(buf, buf, &ctx);
    
	if(hashlib_AESDecrypt(buf, padded_len, buf, &ctx, iv)){
		sprintf(CEMU_CONSOLE, "decrypt success\n");
		hexdump(buf, padded_len, "-- Decrypted Message --");
	}
	else sprintf(CEMU_CONSOLE, "decrypt failed\n");
    //hashlib_AESDecryptBlock(buf, buf, &ctx);
    
    
    stripped_len = hashlib_AESStripPadding(buf, padded_len, buf, SCHM_DEFAULT);
    sprintf(CEMU_CONSOLE, "%s", buf);
    
   // free(padded);
    free(buf);
   // free(buf2);
    free(stripped);
    return 0;
    
}
