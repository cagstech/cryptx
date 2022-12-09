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
	uint8_t secret1[ECDH_PUBKEY_SIZE];		// privkey1 * pubkey2
	uint8_t secret2[ECDH_PUBKEY_SIZE];		// privkey2 * pubkey1
	
	ecdh_ctx test1;
	ecdh_ctx test2;
	ecdh_error_t err;
	
	// Always check for false return value from csrand_init()
	if(!csrand_init(SAMPLING_FAST)) return 1;
	
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nElliptic Curve Diffie-Hellman Demo\n");
	
	timer_Set(1, 0);
	err = ecdh_keygen(&test1, csrand_fill);
	timer_GetSafe(1, TIMER_UP);
	sprintf(CEMU_CONSOLE, "gen of keypair 1 complete in %u ms, exit code:%u\n", err);
	if(!err){
		hexdump(test1.privkey, sizeof test1.privkey, "---keypair 1 private---");
		hexdump(test1.pubkey, sizeof test1.pubkey, "---keypair 1 public---");
	}
	
	
	err = ecdh_keygen(&test2, csrand_fill);
	sprintf(CEMU_CONSOLE, "gen of keypair 2 complete, exit code:%u\n", err);
	if(!err){
		hexdump(test2.privkey, sizeof test2.privkey, "---keypair 2 private---");
		hexdump(test2.pubkey, sizeof test2.pubkey, "---keypair 2 public---");
	}
	
	err = ecdh_secret(&test1, test2.pubkey, secret1);
	sprintf(CEMU_CONSOLE, "gen of secret1 complete, exit code:%u\n", err);
	if(!err)
		hexdump(secret1, sizeof secret1, "---Secret 1 = Privkey1 * Pubkey2 * Cofactor---");
	
	err = ecdh_secret(&test2, test1.pubkey, secret2);
	sprintf(CEMU_CONSOLE, "gen of secret2 complete, exit code:%u\n", err);
	if(!err)
		hexdump(secret2, sizeof secret2, "---Secret 2 = Privkey2 * Pubkey1 * Cofactor---");
	
	return 0;
}
