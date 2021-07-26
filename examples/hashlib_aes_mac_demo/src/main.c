/*
 *--------------------------------------
 * Program Name:
 * Author:
 * License:
 * Description:
 *--------------------------------------
*/

#include <tice.h>
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
    if(label) sprintf(CEMU_CONSOLE, "%s\n", label);
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
    aes_ctx ctx_enc, ctx_mac;
    uint8_t key_aes[KEYSIZE];
    uint8_t key_mac[KEYSIZE];   // ***_MUST_*** use different keys
    uint8_t iv[IV_LEN];
    size_t str_len = strlen(str);
    size_t pad_pt_len = hashlib_AESPaddedSize(str_len);
    size_t ct_len = pad_pt_len + AES_IV_SIZE + AES_MAC_SIZE;
    uint8_t *pad_pt = hashlib_AllocContext(pad_pt_len);
    uint8_t* ct = hashlib_AllocContext(ct_len);
    uint8_t* reverse_ct = hashlib_AllocContext(pad_pt_len);
    
    hashlib_AESPadMessage(str, str_len, pad_pt, SCHM_DEFAULT);
    hexdump(pad_pt, pad_pt_len, "-- Padded message --");
    
    strcpy(CEMU_CONSOLE, "----- AES with MAC AUTH DEMO -----\n");
    sprintf(CEMU_CONSOLE, "The string length is: %u.\nThe padded size is: %u.\nThe full ciphertext size is: %u.\n", str_len, pad_pt_len, ct_len);
    
    // Load the distinct keys into respective key schedules
    hashlib_RandomBytes(key_aes, KEYSIZE);
    hashlib_RandomBytes(key_mac, KEYSIZE);
    hashlib_AESLoadKey(key_mac, &ctx_mac, (KEYSIZE<<3)); // requires size in bits, not bytes
    hashlib_AESLoadKey(key_aes, &ctx_enc, (KEYSIZE<<3)); // requires size in bits, not bytes
    
    // get random IV
    hashlib_RandomBytes(iv, IV_LEN);
    hexdump(iv, AES_BLOCKSIZE, "-- Initialization Vector --");
    
    // call the function macro in the library header
    if(!hashlib_AESAuthEncrypt(pad_pt, pad_pt_len, ct, &ctx_enc, &ctx_mac, iv)){
		strcpy(CEMU_CONSOLE, "Encryption Failed for some reason.\n"); return 1;
	}
    
    // reverse the encryption
    hexdump(ct, ct_len, "-- Result for unmodified message --");
    if(hashlib_AESAuthDecrypt(ct, ct_len, reverse_ct, &ctx_enc, &ctx_mac))
        strcpy(CEMU_CONSOLE, "Decryption Succeeded, MAC Verified.\n");
    else {strcpy(CEMU_CONSOLE, "Decryption Failed, MAC mismatch.\n"); return 1;}
    
    sprintf(CEMU_CONSOLE, "The string is '%s'.\n", reverse_ct);
    // calculate the MAC of blocks0:end-1] of the decrypted msg
    // the output should match the MAC computed above
    strcpy(CEMU_CONSOLE, "-- Chosen Ciphertext Attack Demo --\n");
    strcpy(CEMU_CONSOLE, "Suppose attacker modifies a byte in the ciphertext:\nIn this case, the 12th byte after the IV. (So row 2, position 14 of the hexdump)\n");
    ct[AES_BLOCKSIZE+12] ^= 0x45;
    hexdump(ct, ct_len, NULL);
    strcpy(CEMU_CONSOLE, "Any key to continue\n");
    os_GetKey();
    if(hashlib_AESAuthDecrypt(ct, ct_len, reverse_ct, &ctx_enc, &ctx_mac))
        strcpy(CEMU_CONSOLE, "Decryption Succeeded, MAC Verified.\n");
    else {strcpy(CEMU_CONSOLE, "Decryption Failed, MAC mismatch.\n"); return 1;}
        
    strcpy(CEMU_CONSOLE, "\n");
    
    free(ct);
    free(pad_pt);
    free(reverse_ct);
    return 0;
    
}
