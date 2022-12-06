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
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "ecdh.h"
#define CEMU_CONSOLE ((char*)0xFB0000)

// Defines standardized curve parameters (see http://www.secg.org/sec2-v2.pdf, sect233k1)
// each entry is big-endian encoded
struct Curve sect233k1 = {
	{	0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01},	// poly
	{	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,		// a
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
	{	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,		// b
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01},
	{		// G
		{	0x01,0x72,0x32,0xBA,0x85,0x3A,0x7E,0x73,0x1A,0xF1,0x29,0xF2,0x2F,0xF4,0x14,		// x
			0x95,0x63,0xA4,0x19,0xC2,0x6B,0xF5,0x0A,0x4C,0x9D,0x6E,0xEF,0xAD,0x61,0x26},
		{	0x01,0xDB,0x53,0x7D,0xEC,0xE8,0x19,0xB7,0xF7,0x0F,0x55,0x5A,0x67,0xC4,0x27,		// y
			0xA8,0xCD,0x9B,0xF1,0x8A,0xEB,0x9B,0x56,0xE0,0xC1,0x10,0x56,0xFA,0xE6,0xA3}
	},
	{	0x00,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,			// n
		0x06,0x9D,0x5B,0xB9,0x15,0xBC,0xD4,0x6E,0xFB,0x1A,0xD5,0xF1,0x73,0xAB,0xDF},
	4		// h
};

// defines a null Point to be used for timing resistance
struct Point ta_resist = {0};

// sets a point to 0
#define point_setzero(pt)	\
		memset((pt), 0, sizeof(struct Point))

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
		struct Point r;
		BIGINT slope, a={0}, b={0}, c={0};
		b[(sizeof b)-1] = 3;
		c[(sizeof c)-1] = 2;
		
		// (3x^2 + a)/(2y)
		bigint_mul(a, p->x, p->x);		// a = px^2
		bigint_mul(slope, a, b);		// slope = a * 3
		// we can skip the a step because a is 0
		// we can now also nuke b, constant is used
		bigint_mul(a, p->y, c);			// a = 2(py)
		bigint_invert(b, a);			// b = a^-1
		bigint_mul(slope, slope, b);	// slope = slope * b
		
		// x = slope * slope - 2px
		bigint_mul(r.x, slope, slope);		// rx = slope * slope
		bigint_mul(a, p->x, c);				// a = 2px
		bigint_add(r.x, r.x, a);			// rx = rx - a
		
		// y = (px - rx) * slope - py
		bigint_add(r.y, p->x, r.x);		// y = px - rx
		bigint_mul(r.y, r.y, slope);		// y = y * slope
		bigint_add(r.y, r.y, p->y);		// y = y - py
	}
}


// given ptP and ptQ, return addition result in ptP
void point_add(struct Point *p, struct Point *q){
	// P + Q = R
	// (xp, yp) + (xq, yq) = (xr, yr)
	// Y = (yq - yp)/(xq - xp)		(isn't that some kind of distance)?
	// xr = Y^2 - xp - xq
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
				struct Point r;
				BIGINT slope,a,b,c;
				
				// slope = (py - qy)/(px - qx)
				bigint_add(a, p->x, q->x);		// a = px - qx
				bigint_invert(c, a);			// c = a^1
				bigint_add(b, p->y, q->y);		// b = py - qy
				bigint_mul(slope, b, c);		// slope = b * c
				
				// x = slope * slope - px - qx
				bigint_mul(r.x, slope, slope);		// x = slope * slope
				bigint_add(r.x, r.x, p->x);		// x = x - px
				bigint_add(r.x, r.x, q->x);		// x = x - qx
				
				// y = (px - rx) * slope - py
				bigint_add(r.y, p->x, r.x);		// y = px - rx
				bigint_mul(r.y, r.y, slope);		// y = y * slope
				bigint_add(r.y, r.y, p->y);		// y = y - py
				
				memcpy(p, &r, sizeof(struct Point));
			}
		}
	}
}

// multiplies pt by scalar exp
#define GET_BIT(byte, bitnum) ((byte) & (1<<(bitnum)))
void point_mul_scalar(struct Point *pt, uint8_t *exp, uint8_t explen){
	// multiplies pt by exp, result in pt
	struct Point tmp;
	memcpy(&tmp, pt, sizeof tmp);
	memset(pt, 0, sizeof(struct Point));
	
	
	for(int i = 0; i < explen; i++){
		
		if (GET_BIT(exp[i>>3], i&0x7))
			point_add(pt, &tmp);
		else
			point_add(pt, &ta_resist);	// add 0; timing resistance
		
		point_double(&tmp);
		
	}
}

bool point_isvalid(struct Point *pt)
{
	BIGINT a, b;
	
	if (point_iszero(pt))
	{
		return true;
	}
	else
	{
		// coeff stuff
		bigint_mul(a, pt->x, pt->x);
		bigint_mul(a, a, pt->x);

		//gf2field_add(a, a, coeff_b);
		a[29] ^= 1;		// coeff_b = 1
		bigint_mul(b, pt->y, pt->y);
		bigint_add(a, a, b);
		bigint_mul(b, pt->x, pt->y);
		
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

ecdh_error_t ecdh_keygen(ecdh_ctx *ctx, uint32_t (*randfill)(void *buffer, size_t size)){
	if(ctx==NULL)
		return ECDH_INVALID_ARG;
	
	// privkey is alice 'a'
	// if rand is supplied, assume we need to generate the key
	// if rand is null, assume it's already done
	// if you use this api wrong, its your own fault
	// it will be well documented
	if(randfill != NULL)
		randfill(ctx->privkey, sizeof ctx->privkey - 1);
	ctx->privkey[(sizeof ctx->privkey)-1] = 0;
	
	// copy G from curve parameters to pkey
	// convert to a Point
	// reverse endianness for computational efficiency
	struct Point *pkey = (struct Point*)ctx->pubkey;
	rmemcpy(pkey->x, sect233k1.G.x, sizeof sect233k1.G.x);
	rmemcpy(pkey->y, sect233k1.G.y, sizeof sect233k1.G.y);
	
	// Q = a * G
	// privkey is big-endian encoded
	point_mul_scalar(pkey, (uint8_t*)ctx->privkey, sizeof ctx->privkey);
	
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
	uint8_t cofac = sect233k1.cofactor;
	
	//if(!point_isvalid(pkey)) return ECDH_RPUBKEY_INVALID;
	
	// s = a * Q
	// privkey is big-endian encoded
	point_mul_scalar(pkey, (uint8_t*)ctx->privkey, sizeof ctx->privkey);
	
	// apply cofactor
	while(cofac > 1){
		point_double(pkey);
		cofac>>=1;
	}
	
	return ECDH_OK;
}





