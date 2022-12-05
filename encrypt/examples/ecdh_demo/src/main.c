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

#define ENCRYPT_ENABLE_ADVANCED_MODE
#include <encrypt.h>

//#define	BIGINT_TESTS	1		// uncomment to enable BIGINT tests. Comment to disable.
#define ECDH_TEST	1			// uncomment to enable ECDH unit test. Comment to disable.

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



#ifdef	ECDH_TEST
void ecdh_test(void) {
	uint8_t secret1[ECDH_PUBKEY_SIZE];		// privkey1 * pubkey2
	uint8_t secret2[ECDH_PUBKEY_SIZE];		// privkey2 * pubkey1
	
	ecdh_ctx test1;
	ecdh_ctx test2;
	
	// Always check for false return value from csrand_init()
	
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nElliptic Curve Diffie-Hellman Demo\n");
	
	if(!ecdh_keygen(&test1, csrand_fill))
		sprintf(CEMU_CONSOLE, "gen of keypair 1 successful\n");
	hexdump(test1.privkey, sizeof test1.privkey, "---keypair 1 private---");
	hexdump(test1.pubkey, sizeof test1.pubkey, "---keypair 1 public---");
	//if(!ecdh_keygen(&test2, csrand_fill))
		//sprintf(CEMU_CONSOLE, "gen of keypair 2 successful\n");
	
	//if(!ecdh_secret(&test1, test2.pubkey, secret1))
	//	hexdump(secret1, sizeof secret1, "---Secret 1 = Privkey1 + Pubkey2---");
	
	//if(!ecdh_secret(&test2, test1.pubkey, secret2))
	//	hexdump(secret1, sizeof secret1, "---Secret 2 = Privkey2 + Pubkey1---");
}
#endif

#ifdef BIGINT_TESTS
void bigint_tests(void){
	GF2_BIGINT op1 = {0};
	GF2_BIGINT op2 = {0};
	op1[0] = 2;
	op2[0] = 3;
	
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nGF2_BIGINT Unit Tests\n");
	/*
	sprintf(CEMU_CONSOLE, "\n_ADDITION_\n");
	hexdump(op1, sizeof op1, "---op1---");
	hexdump(op2, sizeof op2, "---op2---");
	gf2_bigint_add(op1, op2);
	hexdump(op1, sizeof op1, "---op1 + op2---");
	
	sprintf(CEMU_CONSOLE, "\n_SUBTRACTION_\n");
	hexdump(op1, sizeof op1, "---op1---");
	hexdump(op2, sizeof op2, "---op2---");
	gf2_bigint_sub(op1, op2);
	hexdump(op1, sizeof op1, "---op1 - op2---");
	
	sprintf(CEMU_CONSOLE, "\n_MULTIPLICATION_\n");
	op1[0] = (uint8_t)csrand_get();
	hexdump(op1, sizeof op1, "---op1---");
	hexdump(op2, sizeof op2, "---op2---");
	gf2_bigint_mul(op1, op2);
	hexdump(op1, sizeof op1, "---op1 * op2---");
	*/
	
	//*((uint8_t*)-1) = 2;
	
	for(int i = 0 ; i < 3; i++){
		op1[0] = (uint8_t)csrand_get();
		sprintf(CEMU_CONSOLE, "\n_INVERSE_\n");
		hexdump(op1, sizeof op1, "---op1---");
		memcpy(op2, op1, sizeof op2);
		gf2_bigint_invert(op1);
		hexdump(op1, sizeof op1, "---op1 ^ -1---");
		gf2_bigint_mul(op1, op2);
		hexdump(op1, sizeof op1, "---op1 * op1 ^ -1---");
	}
	for(int i = 0 ; i < 3; i++){
		csrand_fill(op1, 16);
		sprintf(CEMU_CONSOLE, "\n_INVERSE_\n");
		hexdump(op1, sizeof op1, "---op1---");
		memcpy(op2, op1, sizeof op2);
		gf2_bigint_invert(op1);
		hexdump(op1, sizeof op1, "---op1 ^ -1---");
		gf2_bigint_mul(op1, op2);
		hexdump(op1, sizeof op1, "---op1 * op1 ^ -1---");
	}
}
#endif



int main(void)
{
	if(!csrand_init(SAMPLING_FAST)) return 1;
#ifdef BIGINT_TESTS
	bigint_tests();
#endif
#ifdef ECDH_TEST
	ecdh_test();
#endif
	return 0;
}
