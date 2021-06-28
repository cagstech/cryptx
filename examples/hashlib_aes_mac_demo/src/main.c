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
    aes_ctx ctx_enc, ctx_mac;
    uint8_t key_aes[KEYSIZE];
    uint8_t key_mac[KEYSIZE];   // ***_MUST_*** use different keys
    uint8_t mac_verify[AES_BLOCKSIZE] = {0};
    uint8_t mac[AES_BLOCKSIZE] = {0};
    uint8_t iv[IV_LEN];
    size_t stripped_len;
    
    size_t msg_len = strlen(str);
    size_t padded_len = AES_BLOCKSIZE + hashlib_GetAESPaddedSize(msg_len);
    uint8_t *str_w_mac = hashlib_AllocContext(padded_len);
    uint8_t *mac_padded = hashlib_AllocContext(padded_len);
    uint8_t *padded = hashlib_AllocContext(padded_len);
    uint8_t *out = hashlib_AllocContext(padded_len);
    uint8_t *test = hashlib_AllocContext(padded_len);
    uint8_t *stripped = hashlib_AllocContext(padded_len);
    
    // generate random keys and IV
    hashlib_RandomBytes(key_aes, KEYSIZE);
    hashlib_RandomBytes(key_mac, KEYSIZE);
    hashlib_RandomBytes(iv, IV_LEN);
    
    // pad the input message
    hashlib_PadMessage(str, msg_len, mac_padded, ALG_AES, SCHM_DEFAULT);
    
    // Load the distinct keys into respective key schedules
    hashlib_AESLoadKey(key_mac, &ctx_mac, (KEYSIZE<<3)); // requires size in bits, not bytes
    hashlib_AESLoadKey(key_aes, &ctx_enc, (KEYSIZE<<3)); // requires size in bits, not bytes
    
    
    hashlib_AESOutputMAC(mac_padded, padded_len-AES_BLOCKSIZE, mac, &ctx_mac);
    strcpy(CEMU_CONSOLE, "The MAC of the message is: ");
    for(uint8_t i=0; i<AES_BLOCKSIZE; i++)
        sprintf(CEMU_CONSOLE, "%02X ", mac[i]);
    strcpy(CEMU_CONSOLE, "\n");
    
    // Copy the MAC as the first block of the message to encrypt
    // Copy the original message starting at the next block
    memcpy(str_w_mac, mac, AES_BLOCKSIZE);
    memcpy(&str_w_mac[AES_BLOCKSIZE], mac_padded, padded_len-AES_BLOCKSIZE);
    
    // Pad the new message we will skip... used same scheme, so can just copy the first padded
    // message to the concat.
    
    // encrypt/decrypt the message
    hashlib_AESEncrypt(str_w_mac, padded_len, out, &ctx_enc, iv);
    hashlib_AESDecrypt(out, padded_len, test, &ctx_enc, iv);
    
    // calculate the MAC of blocks[1:end] of the decrypted msg
    // the output should match the MAC computed above
    hashlib_AESOutputMAC(&test[AES_BLOCKSIZE], padded_len-AES_BLOCKSIZE, mac_verify, &ctx_mac);
    
    stripped_len = hashlib_StripPadding(&test[AES_BLOCKSIZE], padded_len-AES_BLOCKSIZE, stripped, ALG_AES, SCHM_DEFAULT);
    sprintf(CEMU_CONSOLE, "The message is '%s' and its size is %u bytes.\n", stripped, stripped_len);
    
    strcpy(CEMU_CONSOLE, "The MAC of the decrypted message is: ");
    for(uint8_t i=0; i<AES_BLOCKSIZE; i++)
        sprintf(CEMU_CONSOLE, "%02X ", mac_verify[i]);
    strcpy(CEMU_CONSOLE, "\n");
    
    if(!memcmp(mac, mac_verify, AES_BLOCKSIZE))
        strcpy(CEMU_CONSOLE, "The MAC of the message matched.");
    else strcpy(CEMU_CONSOLE, "The MAC of the message did not match.");
    strcpy(CEMU_CONSOLE, "\n");
    
    free(mac_padded);
    free(padded);
    free(out);
    free(test);
    free(stripped);
    return 0;
    
}
