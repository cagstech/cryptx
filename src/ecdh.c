/*
 
 a tiny-ecdh implementation for the ez80 CPU
 
## CURVE SPEC ##
using curve sect233k1
define curve T = (p, a, b, G, n, h), where
finite field Fp is defined by:
	f(x) = x^233 + x^74 + 1
curve E: y^2 = x^3 + ax + b over Fp is defined by:
 a = 0000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
 b = 0000 00000000 00000000 00000000 00000000 00000000 00000000 00000001
 x = 017232BA 853A7E73 1AF129F2 2FF41495 63A419C2 6BF50A4C 9D6EEFAD 6126
 y = 01DB 537DECE8 19B7F70F 555A67C4 27A8CD9B F18AEB9B 56E0C110 56FAE6A3
 n = 80 00000000 00000000 00000000 00069D5B B915BCD4 6EFB1AD5 F173ABDF
 h = 04
 
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
bool bigint_iszero(uint8_t *op);
void bigint_setzero(uint8_t *op);
void bigint_isequal(uint8_t *op1, uint8_t *op2);
void bigint_add(uint8_t *op1, uint8_t *op2);
void bigint_sub(uint8_t *op1, uint8_t *op2);

#define CURVE_DEGREE		233
#define ECC_PRV_KEY_SIZE	32
#define ECC_PUB_KEY_SIZE	(ECC_PRV_KEY_SIZE<<1)
#define OVERFLOW_BYTES		2

/*
 ### Main Type Definitions ###
*/

// Bigint for this implementation is a 28-byte big-endian encoded integer
// additional 4 bytes added for if point operations overflow
typedef uint8_t BIGINT[ECC_PRV_KEY_SIZE + OVERFLOW_BYTES];

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

// each entry is big-endian encoded
struct Curve sect233k1 = {
	{	0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x00,	// p
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00},
	{	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	// a
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
	{	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,	// b
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01},
	{		// G
		{	0x01,0x72,0x32,0xBA,0x85,0x3A,0x7E,0x73,0x1A,0xF1,0x29,0xF2,0x2F,0xF4,0x14,		// x
			0x95,0x63,0xA4,0x19,0xC2,0x6B,0xF5,0x0A,0x4C,0x9D,0x6E,0xEF,0xAD,0x61,0x26},
		{	0x01,0xDB,0x53,0x7D,0xEC,0xE8,0x19,0xB7,0xF7,0x0F,0x55,0x5A,0x67,0xC4,0x27,		// y
			0xA8,0xCD,0x9B,0xF1,0x8A,0xEB,0x9B,0x56,0xE0,0xC1,0x10,0x56,0xFA,0xE6,0xA3}
	},
	{	0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x06,
		0x9D,0x5B,0xB9,0x15,0xBC,0xD4,0x6E,0xFB,0x1A,0xD5,0xF1,0x73,0xAB,0xDF},
	4		// h
};
struct Point ta_resist = {0};

typedef enum _ecdh_errors {
	ECDH_OK,
	ECDH_INVALID_ARG,
	ECDH_PRIVKEY_INVALID,
} ecdh_error_t;


// ec point arithmetic prototypes
void point_mul_vect(struct Point *pt, vec_t *exp);
void point_double(struct Point *pt);
void point_add(struct Point *ptP, struct Point *ptQ);

// BIGINT arithmetic/bytearray bitshift prototypes


/*
### Elliptic Curve Diffie-Hellman Main Functions ###
 */


ecdh_error_t ecdh_keygen(uint8_t *pubkey, uint8_t *privkey, size_t klen, uint32_t (randfill*)()){
	if((pubkey==NULL) || (privkey==NULL))
		return ECDH_INVALID_ARG;
	
	// privkey is alice 'a'
	// if rand is supplied, assume we need to generate the key
	// if rand is null, assume it's already done
	// if you use this api wrong, its your own fault
	// it will be well documented
	if(randfill != NULL)
		randfill(privkey, ECC_PRV_KEY_SIZE);
	
	// force klen to equal ECC_PRV_KEY_SIZE
	// it can exceed but any bytes higher than that will be discarded
	if (klen < ECC_PRV_KEY_SIZE)
		return ECDH_PRIVKEY_INVALID;
	
	// copy G from curve parameters to pkey
	// convert to a Point
	// reverse endianness for computational efficiency
	struct Point pkey;
	rmemcpy(pkey.x, secp233k1.G.x, ECC_PRV_KEY_SIZE);
	rmemcpy(pkey.y, secp233k1.G.y, ECC_PRV_KEY_SIZE);
	
	// Q = a * G
	// privkey is big-endian encoded
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
	// privkey is big-endian encoded
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
		
		point_double(&tmp);
	}
	memcpy(pt, &res, sizeof pt);
}

void point_add(struct Point *ptP, struct Point *ptQ){
	// P + Q = R
	// (xp, yp) + (xq, yq) = (xr, yr)
	// Y = (yq - yp)/(xq - xp)		(isn't that some kind of distance)?
	// xr = Y^2 - xp - xq
	// yr = Y(xp - xr) - yp
	// assert: neither P or Q are point at infinity, and Px != Qx
	// if P or Q is point at infinity, R = other point
	// if P = Q, double instead
	// if Px == Qx, set P to point at infinity
	if(!point_iszero(ptQ)){
		if(point_iszero(ptP)){
			memcpy(ptP, ptQ, sizeof ptP);
		} else {
			if(bigint_isequal(ptP->x, ptQ->x)){
				if(bigint_isequal(ptP->y, ptQ->y)){
					point_double(ptP);
				} else {
					memset(ptP, 0, sizeof ptP);
				}
			} else{
				Point res;
				BIGINT deltaY, deltaX;
				
				// compute slope of line between two points
				memcpy(deltaY, ptQ->y, ECC_PRV_KEY_SIZE + OVERFLOW_BYTES);
				memcpy(deltaX, ptQ->x, ECC_PRV_KEY_SIZE + OVERFLOW_BYTES);
				bigint_add(deltaY, ptP->y);		// idk why ref uses add, not sub
				bigint_add(deltaX, ptP->x);		// ...
				bigint_invert(deltaX);
				bigint_mul(deltaX, deltaY);		// deltaX is slope
				
				// compute result X
				memcpy(res.x, deltaX, ECC_PRV_KEY_SIZE + OVERFLOW_BYTES);
				bigint_mul(res.x, res.x);
				bigint_add(res.x, ptP->x);
				bigint_add(res.x, ptQ->x);
				
				// compute result Y
				memcpy(res.y, ptP->x, CC_PRV_KEY_SIZE + OVERFLOW_BYTES);
				bigint_add(res.y, res.x);
				bigint_mul(res.y, deltaX);
				bigint_add(res.y, ptQ->y);
				
				memcpy(ptP, res, sizeof ptP);
			}
		}
	}
}

void point_double(struct Point *pt){
	// P + P = R
	// (xp, yp) + (xp, yp) = (xr, yr)
	// Y = (3(xp)^2 + a) / 2(yp)
	// can we defer division and then divide by [2(yp) * calls_to_double] at the end for speed?
}


static bool point_iszero(struct Point *pt){
	return (bigint_iszero(pt->x) && bigint_iszero(pt->y));
}

static void point_setzero(struct Point *pt){
	bigint_setzero(pt->x);
	bigint_setzero(pt->y);
}

