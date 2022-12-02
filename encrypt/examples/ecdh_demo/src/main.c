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

#define ENCRYPT_ENABLE_ADVANCED_MODE 1
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

/*
int main(void)
{
	uint8_t secret1[ECDH_PUBKEY_SIZE];		// privkey1 * pubkey2
	uint8_t secret2[ECDH_PUBKEY_SIZE];		// privkey2 * pubkey1
    
    // Always check for false return value from csrand_init()
    if(!csrand_init(SAMPLING_FAST)) return 1;
    
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nElliptic Curve Diffie-Hellman Demo\n");
	
	ecdh_ctx test1;
	ecdh_ctx test2;
	
	//if(!ecdh_keygen(&test1, csrand_fill))
	//	sprintf(CEMU_CONSOLE, "gen of keypair 1 successful\n");
	//if(!ecdh_keygen(&test2, csrand_fill))
	//	sprintf(CEMU_CONSOLE, "gen of keypair2 successful\n");
	
	//if(!ecdh_secret(&test1, test2.pubkey, secret1))
	//	hexdump(secret1, sizeof secret1, "---Secret 1 = Privkey1 + Pubkey2---");
	
	//if(!ecdh_secret(&test2, test1.pubkey, secret2))
	//	hexdump(secret1, sizeof secret1, "---Secret 2 = Privkey2 + Pubkey1---");
	
    return 0;
}
*/


int main(void){
	GF2_BIGINT op1 = {0};
	GF2_BIGINT op2 = {0};
	memset(op1, 0, GF2_BIGINT_SIZE - 4);
	memset(op2, 255, GF2_BIGINT_SIZE - 4);
	
	hexdump(op1, sizeof op1, "---op1---");
	hexdump(op2, sizeof op2, "---op2---");
	
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nGF2_BIGINT Unit Tests\n");
	gf2_bigint_add(op1, op2);
	hexdump(op1, sizeof op1, "---op1 + op2---");
	gf2_bigint_sub(op1, op2);
	hexdump(op1, sizeof op1, "---op1 - op2---");
	
	gf2_bigint_mul(op1, op2);
	hexdump(op1, sizeof op1, "---op1 * op2---");
	
	gf2_bigint_invert(op2);
	hexdump(op2, sizeof op2, "---op2 ^ -1---");
}
