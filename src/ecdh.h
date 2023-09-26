
#ifndef ecdh_h
#define ecdh_h

// Defines for algorithm bit/byte widths, bignum max, and key lengths
#define CURVE_DEGREE		233
#define ECC_PRV_KEY_SIZE	30		// largest byte-aligned length < CURVE_DEGREE
#define ECC_BIGINT_MAX_LEN	(ECC_PRV_KEY_SIZE)
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
	struct Point G;
	uint8_t cofactor;
};

// Define ECDH response codes
typedef enum _ecdh_errors {
	ECDH_OK,
	ECDH_INVALID_ARG,
	ECDH_PRIVKEY_INVALID,
	ECDH_RPUBKEY_INVALID
} ecdh_error_t;

// import necessary assembly functions
// asm/ecdh_ops.asm
void rmemcpy(void *dest, void *src, size_t len);		// memcpy that reverses endianness
// ^^ thanks to calc84maniac
bool bigint_iszero(uint8_t *op);
bool point_iszero(struct Point *pt);
bool bigint_isequal(uint8_t *op1, uint8_t *op2);
bool point_isequal(struct Point *pt1, struct Point *pt2);
void bigint_add(BIGINT res, BIGINT op1, BIGINT op2);
void bigint_add_internal(BIGINT op1, BIGINT op2);
void bigint_sub(BIGINT res, BIGINT op1, BIGINT op2);
void bigint_mul(BIGINT res, BIGINT op1, BIGINT op2);
void bigint_invert(BIGINT res, BIGINT op);
void bigint_square(BIGINT res, BIGINT op);
uint8_t ec_poly_get_degree(void* polynomial);

#endif





