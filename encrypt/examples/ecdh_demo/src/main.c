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
#include <encrypt.h>

#define CEMU_CONSOLE ((char*)0xFB0000)
#define MODSIZE 256

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
	uint8_t privkey1[ECDH_PRIVKEY_SIZE];
	uint8_t pubkey1[ECDH_PUBKEY_SIZE];
	uint8_t secret1[ECDH_PUBKEY_SIZE];		// privkey1 * pubkey2
	
	uint8_t privkey2[ECDH_PRIVKEY_SIZE];
	uint8_t pubkey2[ECDH_PUBKEY_SIZE];
	uint8_t secret2[ECDH_PUBKEY_SIZE];		// privkey2 * pubkey1
    
    // Always check for false return value from csrand_init()
    if(!csrand_init(SAMPLING_FAST)) return 1;
	
    csrand_fill(privkey1, ECDH_PRIVKEY_SIZE);
	csrand_fill(privkey2, ECDH_PRIVKEY_SIZE);
    
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nElliptic Curve Diffie-Hellman Demo\n");
	
	if(!ecdh_keygen(pubkey1, privkey1))
		sprintf(CEMU_CONSOLE, "gen of pubkey1 successful\n");
	if(!ecdh_keygen(pubkey2, privkey2))
		sprintf(CEMU_CONSOLE, "gen of pubkey2 successful\n");
	
	if(!ecdh_compute_secret(privkey1, pubkey2, secret1))
		hexdump(secret1, sizeof secret1, "---Secret 1 = Privkey1 + Pubkey2---");
	
	if(!ecdh_compute_secret(privkey2, pubkey1, secret2))
		hexdump(secret1, sizeof secret1, "---Secret 2 = Privkey2 + Pubkey1---");
	
    return 0;
}
