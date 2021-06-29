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

void hexdump(uint8_t *addr, size_t len){
    sprintf(CEMU_CONSOLE, "\n");
    for(size_t rem_len = len, ct=1; rem_len>0; rem_len--, addr++, ct++){
        sprintf(CEMU_CONSOLE, "%02X ", *addr);
        if(!(ct%AES_BLOCKSIZE)) sprintf(CEMU_CONSOLE, "\n");
    }
    sprintf(CEMU_CONSOLE, "\n");
}

int main(void)
{
    // reserve key schedule and key buffer, IV, and encrypt/decrypt buffers
    aes_ctx ctx_enc, ctx_mac;
    uint8_t key_aes[KEYSIZE];
    uint8_t key_mac[KEYSIZE];   // ***_MUST_*** use different keys
    uint8_t mac_verify[AES_BLOCKSIZE] = {0};
    uint8_t iv[IV_LEN];
    size_t str_len = strlen(str);
    size_t ct_len = hashlib_GetAESPaddedSizeMACIV(str_len);
    uint8_t* ct = hashlib_AllocContext(ct_len);
    uint8_t* reverse_ct = hashlib_AllocContext(ct_len);
    
    sprintf(CEMU_CONSOLE, "The string length is: %u.\nThe padded size is: %u.\n", str_len, ct_len);
    
    // Load the distinct keys into respective key schedules
    hashlib_RandomBytes(key_aes, KEYSIZE);
    hashlib_RandomBytes(key_mac, KEYSIZE);
    hashlib_AESLoadKey(key_mac, &ctx_mac, (KEYSIZE<<3)); // requires size in bits, not bytes
    hashlib_AESLoadKey(key_aes, &ctx_enc, (KEYSIZE<<3)); // requires size in bits, not bytes
    
    // get random IV
    hashlib_RandomBytes(iv, IV_LEN);
    
    // call the function macro in the library header
    hashlib_AESEncryptWithMAC(str, str_len, ct, &ctx_enc, &ctx_mac, SCHM_DEFAULT, iv);
    hexdump(ct, ct_len);
    
    // reverse the encryption
    if(hashlib_AESVerifyMAC(ct, ct_len, &ctx_mac))
        strcpy(CEMU_CONSOLE, "The MAC of the message matched.");
    else {strcpy(CEMU_CONSOLE, "The MAC of the message did not match."); return 1;}
    memcpy(iv, ct, AES_BLOCKSIZE);
    hashlib_AESDecrypt(&ct[AES_BLOCKSIZE], ct_len-AES_BLOCKSIZE, reverse_ct, &ctx_enc, iv);
    hexdump(reverse_ct, ct_len);
    // calculate the MAC of blocks0:end-1] of the decrypted msg
    // the output should match the MAC computed above
    
    sprintf(CEMU_CONSOLE, "The string is '%s'.\n", reverse_ct);
    
        
    strcpy(CEMU_CONSOLE, "\n");
    
    free(ct);
    free(reverse_ct);
    return 0;
    
}
