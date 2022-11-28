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

#include <stdint.h>
// import assembly functions necessary for this algorithm
// asm/ecdh_ops.asm
void rmemcpy(void *dest, void *src, size_t len);		// memcpy that reverses endianness
// ^^ thanks to calc84maniac
void bigint_lshift(void *arr, size_t arr_len, uint8_t nbits);	// shift arr n bits to the left
void bigint_rshift(void *arr, size_t arr_len, uint8_t nbits);	// shift arr n bits to the right
// ^^ thanks to Zeda -- WIP

#define ECC_PRV_KEY_SIZE	28
#define ECC_PUB_KEY_SIZE	(ECC_PRV_KEY_SIZE<<1)
#define CURVE_DEGREE		224

/*
 ### Main Type Definitions ###
*/

// Bigint for this implementation is a 28-byte big-endian encoded integer
#define FLAG_LITTLE_ENDIAN	8
typedef uint8_t BIGINT[ECC_PRV_KEY_SIZE];

struct Point {
	BIGINT x;
	BIGINT y;
};

struct Curve {
	BIGINT polynomial;
	BIGINT coeff_a;
	BIIGINT coeff_b;
	Point G;
	BIGINT b_order;
	uint8_t cofactor;
};

// each u32 word is written little-endian
struct Curve secp224k1 = {
	{	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,		// p
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xE5,0x6D},
	{	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,		// a
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
	{	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,		// b
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05},
	{		// G
		{	0xA1,0x45,0x5B,0x33,0x4D,0xF0,0x99,0xDF,0x30,0xFC,0x28,0xA1,0x69,0xA4,		// G.x
			0x67,0xE9,0xE4,0x70,0x75,0xA9,0x0F,0x7E,0x65,0x0E,0xB6,0xB7,0xA4,0x5C},
		{	0x7E,0x08,0x9F,0xED,0x7F,0xBA,0x34,0x42,0x82,0xCA,0xFB,0xD6,0xF7,0xE3,		// G.y
			0x19,0xF7,0xC0,0xB0,0xBD,0x59,0xE2,0xCA,0x4B,0xDB,0x55,0x6D,0x61,0xA5}
	},
	{	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,		// n
		0xDC,0xE8,0xD2,0xEC,0x61,0x84,0xCA,0xF0,0xA9,0x71,0x76,0x9F,0xB1,0xF7},
	1		// h
};
struct Point ta_resist = {0};

typedef enum _ecdh_errors {
	ECDH_OK,
	ECDH_INVALID_ARG,
	ECDH_PRIVKEY_INVALID,
} ecdh_error_t;


// ec point arithmetic prototypes
void point_mul_vect(struct Point *pt, vec_t *exp, uint24_t explen);
void point_double(struct Point *pt);
void point_add(struct Point *pt1, struct Point *pt2);

// BIGINT arithmetic/bytearray bitshift prototypes


/*
### Elliptic Curve Diffie-Hellman Main Functions ###
 */


ecdh_error_t ecdh_keygen(uint8_t *pubkey, uint8_t *privkey, size_t klen, uint32_t (rand*)()){
	if((pubkey==NULL) || (privkey==NULL))
		return ECDH_INVALID_ARG;
	
	// privkey is alice 'a'
	// if rand is supplied, assume we need to generate the key
	// if rand is null, assume it's already done
	// if you use this api wrong, its your own fault
	// it will be well documented
	if(rand!=NULL){
		uint32_t r;
		for(int i=0; i<ECC_NUM_WORDS; i++){
			r = rand();
			memcpy(&privkey[PLATFM_WORD_SIZE*i], &r, PLATFM_WORD_SIZE);
		}
	}
	
	// force klen to equal ECC_PRV_KEY_SIZE
	// it can exceed but any bytes higher than that will be discarded
	if (klen < ECC_PRV_KEY_SIZE)
		return ECDH_PRIVKEY_INVALID;
	
	// copy G from curve parameters to pkey
	// convert to a Point
	// reverse endianness for computational efficiency
	struct Point pkey;
	rmemcpy(pkey.x, secp224k1.G.x, ECC_PRV_KEY_SIZE);
	rmemcpy(pkey.y, secp224k1.G.y, ECC_PRV_KEY_SIZE);
	
	// Q = a * G
	point_mul_vect(pkey, privkey);
	
	// reverse endianness of Point and copy to pubkey
	rmemcpy(pubkey, pkey.x, ECC_PRV_KEY_SIZE);
	rmemcpy(pubkey + ECC_PRV_KEY_SIZE, pkey.y, ECC_PRV_KEY_SIZE);
	
	return ECDH_OK;
}

ecdh_errot_t ecdh_secret(const uint8_t *privkey, const uint8_t *rpubkey, uint8_t *secret){
	if((privkey==NULL) || (rpubkey==NULL) || (output==NULL))
		return ECDH_INVALID_ARG;
	
	// rpubkey = a big-endian encoded bytearray
	// convert to a Point
	// reverse endianness for computational efficiency
	struct Point pkey;
	rmemcpy(pkey.x, rpubkey, ECC_PRV_KEY_SIZE);
	rmemcpy(pkey.y, rpubkey + ECC_PRV_KEY_SIZE, ECC_PRV_KEY_SIZE);
	
	// s = a * Q
	point_mul_vect(pkey, privkey);
	
	// reverse endianness of Point and copy to pubkey
	rmemcpy(secret, pkey.x, ECC_PRV_KEY_SIZE);
	rmemcpy(secret + ECC_PRV_KEY_SIZE, pkey.y, ECC_PRV_KEY_SIZE);
	
	return ECDH_OK;
}

/*
 ### EC Point Arithmetic Functions ###
 */

#define GET_BIT(byte, bitnum) ((byte) & (1<<(bitnum)))
void point_mul_vect(struct Point *pt, uint8_t *exp){
// multiplies pt by exp, result in pt
	struct Point tmp;
	struct Point res = {0};		// point-at-infinity
	memcpy(&tmp, pt, sizeof tmp);
	
	for(i = CURVE_DEGREE; i >= 0; i--){
		if (GET_BIT(exp[i>>3], i&0x7))
			point_add(&res, &tmp);
		else
			point_add(&res, &ta_resist);	// add 0; timing resistance
		
		// point_double(&tmp);
		// isn't just a x2 the same thing?
		// also if its all little endian, isn't rshift a *2, not an lshift?
		rshift_barr(tmp.x, sizeof tmp.x);
		rshift_barr(tmp.y, sizeof tmp.y);
	}
	memcpy(pt, &res, sizeof pt);
}

void point_add(struct Point *pt1, struct Point *pt2){
	// how in the 37 layers of hell do you do this??
	// is this just a straight addition of two points or some weird bs?
	// I'm at like 16% soul right about now
}

void point_double(struct Point *pt){
	// same question here
	// https://www.nayuki.io/page/elliptic-curve-point-addition-in-projective-coordinates
	// it seems obnoxiously complex and computationally intensive
}


/*
 ### Vector Arithmetic Functions ###
 */

static void vect_add(vec_t *v1, vec_t *v2){
	
}

static void vect_double(vec_t *v){
	vect_lshift(v, 1);
}



