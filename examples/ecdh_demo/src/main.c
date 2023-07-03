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
#include <cryptx.h>

#define CEMU_CONSOLE ((char*)0xFB0000)
void hexdump(uint8_t *addr, size_t len, uint8_t *label){
	if(label) sprintf(CEMU_CONSOLE, "\n%s\n", label);
	else sprintf(CEMU_CONSOLE, "\n");
	for(size_t rem_len = len, ct=1; rem_len>0; rem_len--, addr++, ct++){
		sprintf(CEMU_CONSOLE, "%02X ", *addr);
		if(!(ct%CRYPTX_AES_BLOCK_SIZE)) sprintf(CEMU_CONSOLE, "\n");
	}
	sprintf(CEMU_CONSOLE, "\n");
}


int main(void)
{
	uint8_t secret1[CRYPTX_ECDH_SECRET_LEN];		// privkey1 * pubkey2
	uint8_t secret2[CRYPTX_ECDH_SECRET_LEN];		// privkey2 * pubkey1
	uint8_t pubkey1[CRYPTX_ECDH_PUBKEY_LEN];		// privkey1 * pubkey2
	uint8_t pubkey2[CRYPTX_ECDH_PUBKEY_LEN];		// privkey2 * pubkey1
	
	uint8_t privkey1[CRYPTX_ECDH_PRIVKEY_LEN];
	uint8_t privkey2[CRYPTX_ECDH_PRIVKEY_LEN];
	ecdh_error_t err = 0;
	
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nElliptic Curve Diffie-Hellman Demo\n");
	
	CRYPTX_ECDH_GENERATE_PRIVKEY(privkey1);
	CRYPTX_ECDH_GENERATE_PRIVKEY(privkey2);
	err = cryptx_ecdh_publickey(privkey1, pubkey1);
	sprintf(CEMU_CONSOLE, "gen of keypair 1 complete, exit code:%u\n", err);
	if(!err){
		hexdump(privkey1, CRYPTX_ECDH_PRIVKEY_LEN, "---keypair 1 private---");
		hexdump(pubkey1, CRYPTX_ECDH_PUBKEY_LEN, "---keypair 1 public---");
	}
	
	
	err = cryptx_ecdh_publickey(privkey2, pubkey2);
	sprintf(CEMU_CONSOLE, "gen of keypair 2 complete, exit code:%u\n", err);
	if(!err){
		hexdump(privkey2, CRYPTX_ECDH_PRIVKEY_LEN, "---keypair 2 private---");
		hexdump(pubkey2, CRYPTX_ECDH_PUBKEY_LEN, "---keypair 2 public---");
	}
	
	err = cryptx_ecdh_secret(privkey1, pubkey2, secret1);
	sprintf(CEMU_CONSOLE, "gen of secret1 complete, exit code:%u\n", err);
	if(!err)
		hexdump(secret1, sizeof secret1, "---Secret 1 = Privkey1 * Pubkey2 * Cofactor---");
	
	err = cryptx_ecdh_secret(privkey2, pubkey1, secret2);
	sprintf(CEMU_CONSOLE, "gen of secret2 complete, exit code:%u\n", err);
	if(!err)
		hexdump(secret2, sizeof secret2, "---Secret 2 = Privkey2 * Pubkey1 * Cofactor---");
	
	return 0;
}
