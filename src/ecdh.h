
#ifndef ecdh_h
#define ecdh_h

// Defines for algorithm bit/byte widths, bignum max, and key lengths
#define CURVE_DEGREE		233
#define ECC_PRV_KEY_SIZE	29		// largest byte-aligned length < CURVE_DEGREE
#define ECC_BIGINT_MAX_LEN	(ECC_PRV_KEY_SIZE + 3)
#define ECC_PUB_KEY_SIZE	(ECC_BIGINT_MAX_LEN<<1)

// Bigint for this implementation is a 32-byte big-endian encoded integer
// 3 padding bytes appended to the end, in case a mul operation overflows
// prior to modulo poly
typedef uint8_t BIGINT[ECC_BIGINT_MAX_LEN];

// Defines a GF(2^m) point
struct Point {
	BIGINT x;
	BIGINT y;
};

// A structure for defining curve parameters
struct Curve {
	BIGINT polynomial;
	BIGINT coeff_a;
	BIGINT coeff_b;
	struct Point G;
	BIGINT b_order;
	uint8_t cofactor;
};

// Define ECDH key context
typedef struct _ecdh_ctx {
	uint8_t privkey[ECC_PRV_KEY_SIZE];
	uint8_t pubkey[ECC_PUB_KEY_SIZE];
} ecdh_ctx;

// Define ECDH response codes
typedef enum _ecdh_errors {
	ECDH_OK,
	ECDH_INVALID_ARG,
	ECDH_PRIVKEY_INVALID,
} ecdh_error_t;

// import necessary assembly functions
// asm/ecdh_ops.asm
void rmemcpy(void *dest, void *src, size_t len);		// memcpy that reverses endianness
// ^^ thanks to calc84maniac
bool bigint_iszero(uint8_t *op);
void bigint_setzero(uint8_t *op);
bool bigint_isequal(uint8_t *op1, uint8_t *op2);
void bigint_add(uint8_t *op1, uint8_t *op2);
void bigint_sub(uint8_t *op1, uint8_t *op2);

#endif





