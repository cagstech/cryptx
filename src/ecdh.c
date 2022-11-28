/*
 
 a tiny-ecdh implementation for the ez80 CPU
 
## CURVE SPEC ##
using curve secp224k1
define curve T = (p, a, b, G, n, h), where
finite field Fp is defined by:
	p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFE56D
	f(x) = 2^224 − 2^32 − 2^12 − 2^11 − 2^9 − 2^7 − 2^4 − 2 − 1
curve E: y^2 = x^3 + ax + b over Fp is defined by:
	a = 00000000 00000000 00000000 00000000 00000000 00000000 00000000
	b = 00000000 00000000 00000000 00000000 00000000 00000000 00000005
	G(x) = A1455B33 4DF099DF 30FC28A1 69A467E9 E47075A9 0F7E650E B6B7A45C
	G(y) = 7E089FED 7FBA3442 82CAFBD6 F7E319F7 C0B0BD59 E2CA4BDB 556D61A5
	n = 00000000 00000000 00000000 0001DCE8 D2EC6184 CAF0A971 769FB1F7
	h = 01
 
## KEYGEN ## generate key pair (d, Q)
d is secret. Assert d in range [1, n-1] (random).
Q = d*G
output (d, Q)
 
## PUBKEY VALID ##
assert Q != infinity point
assert xQ, yQ are of degree <= m-1
assert nQ = infinity point
if h = 1, skip final assertion
 
## SECRET COMPUTE ##
inputs:
	private key d(alice) associated with T(alice)
	public key Q(bob) associated with T(bob)
P = (x, y) = h * d(alice) * Q(bob)
if P = infinite point, invalid
output x as shared secret field
(optional, but recommended) pass x to a KDF to generate symmetric key
 */

#define ECC_PRV_KEY_SIZE	28
#define ECC_PUB_KEY_SIZE	(ECC_PRV_KEY_SIZE<<1)
#define CURVE_DEGREE		224

#define PLATFM_WORD_SIZE	sizeof(uint32_t)
#define ECC_NUM_WORDS		(ECC_PRV_KEY_SIZE / PLATFM_WORD_SIZE)

// main type definitions for variables
typedef uint32_t vec_t[ECC_NUM_WORDS];	// should be 24 bytes
struct Point {
	vec_t x;
	vec_t y;
};
struct Curve {
	vec_t polynomial;
	vec_t coeff_a;
	vec_t coeff_b;
	Point base;
	vec_t b_order;
	uint8_t cofactor;
};

#define

// each u32 word is written little-endian
struct Curve secp224k1 = {
	{0xFFFFE56D, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF},	// p
	{0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000},	// a
	{0x00000005, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000},	// b
	{
		{0xB6B7A45C, 0x0F7E650E, 0xE47075A9, 0x69A467E9, 0x30FC28A1, 0x4DF099DF, 0xA1455B33},	// x
		{0x556D61A5, 0xE2CA4BDB, 0xC0B0BD59, 0xF7E319F7, 0x82CAFBD6, 0x7FBA3442, 0x7E089FED}	// y
	},		// G
	{0x769FB1F7, 0xCAF0A971, 0xD2EC6184, 0x0001DCE8, 0x00000000, 0x00000000, 0x00000000},	// n
	1		// h
};

typedef enum _ecdh_errors {
	ECDH_OK,
	ECDH_INVALID_ARG,
	ECDH_PRIVKEY_INVALID,
} ecdh_error_t;



void ecdh_point_mul_vect(struct Point *pt, vec_t *exp);
void ecdh_point_double(struct Point *pt);
bool ecdh_vec_getbit(vec_t *v, uint24_t bit);
void ecdh_point_add(struct Point *pt1, struct Point *pt2);

ecdh_error_t ecdh_keygen(uint8_t *pubkey, uint8_t *privkey, uint32_t (rand*)()){
	if((pubkey==NULL) || (privkey==NULL))
		return ECDH_INVALID;
	
	if(rand!=NULL){
		uint32_t r;
		for(int i=0; i<ECC_NUM_WORDS; i++){
			r = rand();
			memcpy(&privkey[PLATFM_WORD_SIZE*i], &r, PLATFM_WORD_SIZE);
		}
	}
	
	// to-do: check for privkey sanity
	
	struct Point pkey;
	memcpy(pkey.x, secp224k1.base.x, ECC_PRV_KEY_SIZE);
	memcpy(pkey.y, secp224k1.base.y, ECC_PRV_KEY_SIZE);
	ecdh_point_mul_vect(pkey, (uint32_t*)privkey);
	
	// point multiplication to generate pubkey
	
	return ECDH_OK;
}


#define GET_BIT(byte, bitnum) ((byte) & (1<<(bitnum)))
void ecdh_point_mul_vect(struct Point *pt, vec_t *exp){
	struct Point tmp = {0};
	struct Point ta_resist = {0};
	uint8_t *exp_octets = (uint8_t*)exp;
	
	for(i = nbits; i >= 0; i--){
		ecdh_point_double(&tmp);
		if (GET_BIT(exp_octets[bit>>3], bit&0x7))
			ecdh_point_add(&tmp, pt);
		else
			ecdh_point_add(&tmp, &ta_resist);	// add 0; timing resistance
	}
	memcpy(pt, &tmp, sizeof pt);
}


void ecdh_point_add(struct Point *pt1, struct Point *pt2){
	// help!!!
}
