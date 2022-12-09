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

#define ENCRYPT_ENABLE_GF2_BIGINT
#define ENCRYPT_ENABLE_ECC_POINT_ARITHMETIC
#include <encrypt.h>

//#define	BIGINT_TESTS	1		// uncomment to enable BIGINT tests. Comment to disable.
#define POINT_ARITH_TESTS	1
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
	ecdh_error_t err;
	
	// Always check for false return value from csrand_init()
	
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nElliptic Curve Diffie-Hellman Demo\n");
	
	err = ecdh_keygen(&test1, csrand_fill);
	sprintf(CEMU_CONSOLE, "gen of keypair 1 complete, exit code:%u\n", err);
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
		hexdump(secret1, sizeof secret1, "---Secret 1 = Privkey1 + Pubkey2---");
	
	err = ecdh_secret(&test2, test1.pubkey, secret2);
	sprintf(CEMU_CONSOLE, "gen of secret2 complete, exit code:%u\n", err);
	if(!err)
		hexdump(secret2, sizeof secret2, "---Secret 2 = Privkey2 + Pubkey1---");
	
}
#endif

#ifdef POINT_ARITH_TESTS
void point_arith_tests(void){
	uint8_t test_point_x[] = {0x01,0x72,0x32,0xBA,0x85,0x3A,0x7E,0x73,0x1A,0xF1,0x29,0xF2,0x2F,0xF4,0x14,
		 0x95,0x63,0xA4,0x19,0xC2,0x6B,0xF5,0x0A,0x4C,0x9D,0x6E,0xEF,0xAD,0x61,0x26};
	uint8_t test_point_y[] = {0x01,0xDB,0x53,0x7D,0xEC,0xE8,0x19,0xB7,0xF7,0x0F,0x55,0x5A,0x67,0xC4,0x27,
		 0xA8,0xCD,0x9B,0xF1,0x8A,0xEB,0x9B,0x56,0xE0,0xC1,0x10,0x56,0xFA,0xE6,0xA3};
	
	ecc_point p1, p2;
	gf2_bigint_frombytes(p1.x, test_point_x, sizeof test_point_x, false);
	gf2_bigint_frombytes(p1.y, test_point_y, sizeof test_point_y, false);
	memcpy(&p2, &p1, sizeof p2);
	
	hexdump(&p1, sizeof p1, "---Point 1---");
	hexdump(&p2, sizeof p2, "---Point 2---");
	
	ecc_point_double(&p1);
	hexdump(&p1, sizeof p1, "---Point 1 Double---");
	
	hexdump(&p1, sizeof p1, "---Point 1---");
	hexdump(&p2, sizeof p2, "---Point 2---");
	ecc_point_add(&p1, &p2);
	hexdump(&p1, sizeof p1, "---Point 1 + Point 2---");
}
#endif

#ifdef BIGINT_TESTS
void bigint_tests(void){
	GF2_BIGINT op1 = {0};
	GF2_BIGINT op2 = {0};
	GF2_BIGINT res = {0};
	op1[0] = 2;
	op2[0] = 3;
	
	sprintf(CEMU_CONSOLE, "\n\n----------------------------------\nGF2_BIGINT Unit Tests\n");
	sprintf(CEMU_CONSOLE, "\n_ADDITION_\n");
	hexdump(op1, sizeof op1, "---op1---");
	hexdump(op2, sizeof op2, "---op2---");
	gf2_bigint_add(res, op1, op2);
	hexdump(res, sizeof res, "---op1 + op2---");
	
	sprintf(CEMU_CONSOLE, "\n_SUBTRACTION_\n");
	hexdump(op1, sizeof op1, "---op1---");
	hexdump(op2, sizeof op2, "---op2---");
	gf2_bigint_sub(res, op1, op2);
	hexdump(res, sizeof res, "---op1 - op2---");
	
	sprintf(CEMU_CONSOLE, "\n_MULTIPLICATION_\n");
	hexdump(op1, sizeof op1, "---op1---");
	hexdump(op2, sizeof op2, "---op2---");
	gf2_bigint_mul(res, op1, op2);
	hexdump(res, sizeof res, "---op1 * op2---");
	
	op1[0] = (uint8_t)csrand_get();
	sprintf(CEMU_CONSOLE, "\n_INVERSE_\n");
	hexdump(op1, sizeof op1, "---op1---");
	gf2_bigint_invert(res, op1);
	hexdump(res, sizeof res, "---op1 ^ -1---");
	gf2_bigint_mul(res, res, op1);
	hexdump(res, sizeof res, "---op1 * op1 ^ -1---");

}
#endif



int main(void)
{
	if(!csrand_init(SAMPLING_FAST)) return 1;
#ifdef BIGINT_TESTS
	bigint_tests();
#endif
#ifdef POINT_ARITH_TESTS
	point_arith_tests();
#endif
#ifdef ECDH_TEST
	ecdh_test();
#endif
	return 0;
}
