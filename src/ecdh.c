/*
 
 a tiny-ecdh implementation for the ez80 CPU
 
## CURVE SPEC ##
using curve sect233k1
define curve T = (p, a, b, G, n, h), where
finite field Fp is defined by:
 poly: 00000200 00000000 00000000 00000000 00000000 00000400 00000000 00000001
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
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

void cryptx_csrand_fill(void* buffer, size_t len);

#include "ecdh.h"
#define CEMU_CONSOLE ((char*)0xFB0000)

// Defines standardized curve parameters (see http://www.secg.org/sec2-v2.pdf, sect233k1)
// each entry is big-endian encoded
struct Curve sect233k1 = {
	{	0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01},	// poly
	// a = 0, b = 1
	{		// G
		{	0x01,0x72,0x32,0xBA,0x85,0x3A,0x7E,0x73,0x1A,0xF1,0x29,0xF2,0x2F,0xF4,0x14,
			0x95,0x63,0xA4,0x19,0xC2,0x6B,0xF5,0x0A,0x4C,0x9D,0x6E,0xEF,0xAD,0x61,0x26},
		{	0x01,0xDB,0x53,0x7D,0xEC,0xE8,0x19,0xB7,0xF7,0x0F,0x55,0x5A,0x67,0xC4,0x27,
			0xA8,0xCD,0x9B,0xF1,0x8A,0xEB,0x9B,0x56,0xE0,0xC1,0x10,0x56,0xFA,0xE6,0xA3}
	},
	4		// h
};

// defines a null Point to be used for timing resistance
struct Point ta_resist = {0};

/*
 Point Arithmetic Functions
 */

// given ptP, ptQ, and slope, return addition/double result in ptp

// given pt, return point double result in pt
void point_double(struct Point *p){
	// P + P = R
	// (xp, yp) + (xp, yp) = (xr, yr)
	// Y = (3(xp)^2 + a) / 2(yp)
	// can we defer division and then divide by [2(yp) * calls_to_double] at the end for speed?
	
	if(bigint_iszero(p->y)) memset(p, 0, sizeof(struct Point));
	else{
		BIGINT l;
		
		bigint_invert(l, p->x);
		bigint_mul(l, l, p->y);
		bigint_add(l, l, p->x);
		bigint_square(p->y, p->x);
		bigint_square(p->x, l);

		//bigint_inc(l);	if coeff_a != 0

		bigint_add(p->x, p->x, l);
		bigint_mul(l, l, p->x);
		bigint_add(p->y, p->y, l);
		bigint_add(p->y, p->y, p->x);
	}
}


// given ptP and ptQ, return addition result in ptP
void point_add(struct Point *p, struct Point *q){
	// P + Q = R
	// (xp, yp) + (xq, yq) = (xr, yr)
	// Y = (yq - yp)/(xq - xp)		(isn't that some kind of distance)?
	// xr = Y^2 + Y - xp - xq
	// yr = Y(xp - xr) - yp
	// assert: neither P or Q are point at infinity, and Px != Qx
	// if P or Q is point at infinity, R = other point
	// if P = Q, double instead
	// if Px == Qx, set P to point at infinity
		
	if(!point_iszero(q)) {
		if(point_iszero(p)) memcpy(p, q, sizeof(struct Point));
		else {
			if(point_isequal(p, q)) point_double(p);
			else if(bigint_isequal(p->x, q->x)) memset(p, 0, sizeof(struct Point));
			else {
				
				BIGINT t1,t2,t3;
				
				// Yp + Yq
				bigint_add(t1, p->y, q->y);
				// Xp + Xq
				bigint_add(t2, p->x, q->x);
				// inv(t2)
				bigint_invert(t3, t2);
				// (Py + Yq) / (Xp + Xq)
				bigint_mul(t1, t1, t3);		// t1 = slope
				
				// slope^2
				bigint_square(t3, t1);
				// + Xp + Xq
				bigint_add(t3, t3, t2);	// free up t2
				// + slope
				bigint_add(t3, t3, t1);	// xres in t3
				
				// Xp - Xres
				bigint_add(t2, p->x, t3);	// free up t3
				memcpy(p->x, t3, sizeof t3);	// output resx
				// * slope
				bigint_mul(t2, t2, t1);
				// + Yq
				bigint_add(t2, t2, p->y);
				
				// computed y + computed x = y, output y
				bigint_add(p->y, t2, p->x);
				
			}
		}
	}
}

// multiplies pt by scalar exp
#define GET_BIT(byte, bitnum) ((byte) & (1<<(bitnum)))
void point_mul_scalar(struct Point *p, uint8_t *exp, int explen){
	// multiplies pt by exp, result in pt
	struct Point tmp;
	memcpy(&tmp, p, sizeof tmp);
	memset(p, 0, sizeof(struct Point));
	
	
	for(int i = (explen-1); i >= 0; i--){
		
		point_double(p);
		if (GET_BIT(exp[i>>3], i&0x7))
			point_add(p, &tmp);
		else
			point_add(p, &ta_resist);	// add 0; timing resistance
	}
}

bool point_isvalid(struct Point *p)
{
	BIGINT a, b;
	
	if (point_iszero(p))
	{
		return true;
	}
	else
	{
		// check if y^2 + x*y = x^3 + 1 holds
		// coeff stuff
		bigint_mul(a, p->x, p->x);
		bigint_mul(a, a, p->x);
		a[0] ^= 1;		// coeff_b = 1, so just xor LSB with 1
		
		// y^2
		bigint_mul(b, p->y, p->y);
		
		// sub y^2 from both sides
		bigint_add(a, a, b);
		// x * y
		bigint_mul(b, p->x, p->y);
		
		return bigint_isequal(a, b);
	}
}
#define AES_BLOCKSIZE 16
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


/*
### Elliptic Curve Diffie-Hellman Main Functions ###
 */
#define BASE_ORDER_BYTES	29
ecdh_error_t ecdh_init(ecdh_ctx *ctx){
	if(ctx==NULL)
		return ECDH_INVALID_ARG;
	
	// privkey is alice 'a'
	// if rand is supplied, assume we need to generate the key
	// if rand is null, assume it's already done
	// if you use this api wrong, its your own fault
	// it will be well documented
	
	cryptx_csrand_fill(ctx->privkey, BASE_ORDER_BYTES);
	
	// copy G from curve parameters to pkey
	// convert to a Point
	// reverse endianness for computational efficiency
	struct Point *pkey = (struct Point*)ctx->pubkey;
	rmemcpy(pkey->x, sect233k1.G.x, sizeof sect233k1.G.x);
	rmemcpy(pkey->y, sect233k1.G.y, sizeof sect233k1.G.y);
	
	// Q = a * G
	// privkey is big-endian encoded
	point_mul_scalar(pkey, (uint8_t*)ctx->privkey, (sizeof ctx->privkey)<<3);
	
	return ECDH_OK;
}

ecdh_error_t ecdh_secret(const ecdh_ctx *ctx, const uint8_t *rpubkey, uint8_t *secret){
	if((ctx==NULL) || (rpubkey==NULL) || (secret==NULL))
		return ECDH_INVALID_ARG;
	
	// rpubkey = a big-endian encoded bytearray
	// convert to a Point
	// reverse endianness for computational efficiency
	memcpy(secret, rpubkey, sizeof(struct Point));
	struct Point *pkey = (struct Point*)secret;
	uint8_t cofactor = sect233k1.cofactor;
	
	if(point_iszero(pkey) || (!point_isvalid(pkey))) return ECDH_RPUBKEY_INVALID;
	
	// s = a * Q
	// privkey is big-endian encoded
	point_mul_scalar(pkey, (uint8_t*)ctx->privkey, (sizeof ctx->privkey)<<3);
	
	// apply cofactor
	for(; cofactor > 1; cofactor>>=1) point_double(pkey);
	
	return ECDH_OK;
}





