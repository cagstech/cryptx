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
int main(void)
{
    // reserve key schedule and key buffer, IV, and encrypt/decrypt buffers
    aes_ctx ctx;
    uint8_t key[KEYSIZE];
    uint8_t iv[IV_LEN];
    size_t stripped_len;
    
    size_t msg_len = strlen(str);
    size_t padded_len = hashlib_AESPaddedSize(msg_len);
    uint8_t *padded = hashlib_AllocContext(padded_len);
    uint8_t *out = hashlib_AllocContext(padded_len);
    uint8_t *test = hashlib_AllocContext(padded_len);
    uint8_t *stripped = hashlib_AllocContext(padded_len);
    
    // generate random key and IV
    hashlib_RandomBytes(key, KEYSIZE);
    hashlib_RandomBytes(iv, IV_LEN);
    
    // pad the input message
    hashlib_AESPadMessage(str, msg_len, padded, SCHM_DEFAULT);
    
    // load the key into the key schedule
    hashlib_AESLoadKey(key, &ctx, KEYSIZE); // requires size in bits, not bytes
    
    hashlib_AESEncrypt(padded, padded_len, out, &ctx, iv);
    hashlib_AESDecrypt(out, padded_len, test, &ctx, iv);
    
    stripped_len = hashlib_AESStripPadding(test, padded_len, stripped, SCHM_DEFAULT);
    sprintf(CEMU_CONSOLE, "The message is '%s' and its size is %u bytes.\n", stripped, stripped_len);
    
    free(padded);
    free(out);
    free(test);
    free(stripped);
    return 0;
    
}
