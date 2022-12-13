/**
 *	@file hashlib.h
 *	@brief	Provides cryptographic hashing for the TI--84+ CE
 *	@author Anthony @e ACagliano Cagliano
 *	@author Adam @e beck Beckingham
 *	@author commandblockguy
 *
 * 1. Hashes: SHA256
 * 2. HMAC: SHA256
 * 3. MGF1
 * 4. PBKDF2
 * 5. Buffer comparison
 * 6. Buffer to hexstring
 */

#ifndef hashlib_h
#define hashlib_h

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

//******************************************************************************************
/*	INTERNAL OBJECT DEFINITIONS
 
	This section defines INTERNAL OBJECTS used by the library in functions not
	exposed to the users. These are here so that metadata portions of the context
	structures defined later are correct.
 */

// Private Struct Definitions for Hash State Contexts
struct cryptx_priv_hash_sha256_state {
	uint8_t data[64];		/**< holds sha-256 block for transformation */
	uint8_t datalen;		/**< holds the current length of data in data[64] */
	uint8_t bitlen[8];		/**< holds the current length of transformed data */
	uint32_t state[8];		/**< holds hash state for transformed data */
};
typedef union {
	struct cryptx_priv_hash_sha256_state sha256;
} cryptx_hash_private_h;

// Private Struct Definitions for HMAC State Contexts
struct cryptx_priv_hmac_sha256_state {
	uint8_t ipad[64];       /**< holds the key xored with a magic value to be hashed with the inner digest */
	uint8_t opad[64];       /**< holds the key xored with a magic value to be hashed with the outer digest */
	uint8_t data[64];		/**< holds sha-256 block for transformation */
	uint8_t datalen;		/**< holds the current length of data in data[64] */
	uint8_t bitlen[8];		/**< holds the current length of transformed data */
	uint32_t state[8];		/**< holds hash state for transformed data */
};
typedef union {
	struct cryptx_priv_hmac_sha256_state sha256;
} cryptx_hmac_private_h;


//******************************************************************************************
/*	Cryptographic Hashes
 
	A cryptographic hash is a cryptographic `primitve` (def: a low-level algorithm used
	to build protocols) that is used for data integrity verification. It is similar to a
	checksum, but unlike checksums, which can be easily fooled, cryptographic hashes
	are a lot harder to fool due to the nature of their construction. The general use of
	a hash is as follows:
	(1) The party sending a message hashes it and includes that hash as part of the message.
	(2) The recipient hashes the message (except the hash) themselves and then compares that hash
		with the one included in the message.
	(3) If the hashes match, the message is complete and unaltered. If the hashes do not match,
		the message is incomplete or has been tampered with and should be discarded
		(and possibly a new copy of the message requested from origin). */


/*******************************************
 * @struct cryptx\_hash\_ctx
 * Defines a context for storing hash-state data.
 */
struct cryptx_hash_ctx {
	bool (*init)(void* ctx);
	void (*update)(void* ctx, const void* data, size_t len);
	void (*final)(void* ctx, void* output);
	uint8_t digest_len;
	cryptx_hash_private_h metadata;
};
 
 /*******************************
  * @enum cryptx\_hash\_algorithms
  * Idenitifiers for selecting hash types.
  */
enum cryptx_hash_algorithms {
    SHA256,             /**< algorithm type identifier for SHA-256 */
};

/***********************************
 * @def CRYPTX\_SHA256\_DIGEST\_LEN
 * Byte length of SHA-256 digest.
 */
#define CRYPTX_SHA256_DIGEST_LEN   32

/**************************************************************
 *	@brief Initializes a hash-state context for a specific hash algorithm.
 *	@param[in] context	Pointer to a hash-state context.
 *  @param[in] hash_alg	The numeric ID of the hashing algorithm to use. See @b cryptx_hash_algorithms.
 *  @return @b true if hash initialization succeeded, @b false if failed.
 *  @note Uses 516 bytes of fastMem starting at 0xE30800.
 */
bool cryptx_hash_init(struct cryptx_hash_ctx* context, uint8_t hash_alg);

/*********************************************************
 *	@brief Updates the hash-state for a given block of data.
 *	@param[in] context	Pointer to a hash-state context.
 *	@param[in] data		Pointer to a block of data to hash..
 *	@param[in] len		Size of the @b data to hash.
 *	@note Uses 516 bytes of fastMem starting at 0xE30800.
 *	@warning Calling this on a context that has not been initialized may have
 *	unpredictable results.
 */
void cryptx_hash_update(struct cryptx_hash_ctx* context, const void* data, size_t len);

/*****************************************************
 *	@brief Output digest for current hash-state (preserves state).
 *	@param[in] context	Pointer to a hash-state context.
 *	@param[out]	digest	Pointer to a buffer to write digest to.
 *	@note @b digest must be at large enough to hold the hash digest.
 *	You can retrieve the necessary size by accessing the @b digest_len
 *	member of an initialized @b cryptx_hash_ctx.
 *	@note Uses 516 bytes of fastMem starting at 0xE30800.
 *  @warning Calling this on a context that has not been initialized may have
 *	unpredictable results.
 */
void cryptx_hash_final(struct cryptx_hash_ctx* context, void* digest);

/*********************************************************
 *	@brief Computes a digest of arbitrary length for a given block of data.
 *	@param[in]	data	Pointer to data to hash.
 *	@param[in]	datalen	Size of @b data to hash.
 *	@param[out] outbuf	Pointer to buffer to write digest to.
 *	@param[in]	outlen 	Number of bytes to write to @b outbuf.
 *  @param[in]	hash_alg	The numeric ID of the hashing algorithm to use. See @b cryptx_hash_algorithms.
 *	@note @b outbuf must be at least @b outlen bytes large.
 *	@note Uses 516 bytes of fastMem starting at 0xE30800.
 */
bool cryptx_hash_mgf1(
			const void* data,
			size_t datalen,
			void* outbuf,
			size_t outlen,
			uint8_t hash_alg);


//******************************************************************************************
/*	Hash-Based Message Authentication Code (HMAC)

	An HMAC is a keyed hash. The hash-state of an HMAC context is transformed using a
	key during initialization. The state is then transformed again during digest
	computation. This results in a hash that can only be validated by another HMAC
	implementation using the correct key. */


/*************************************
 * @struct cryptx\_hmac\_ctx
 * Defines a context for storing HMAC-state data.
 */
struct cryptx_hmac_ctx {
    bool (*init)(void* ctx, const void* key, size_t keylen);
    void (*update)(void* ctx, const void* data, size_t len);
    void (*final)(void* ctx, void* output);
	uint8_t digest_len;
	cryptx_hmac_private_h metadata;
};

/*************************************************************
 *	@brief Initializes an HMAC-state context for a specific hash algorithm.
 *	@param[in] context	Pointer to an HMAC-state context.
 *	@param[in] key		Pointer to a key used to initialize the HMAC state.
 *	@param[in] keylen	Length of the @b key.
 *  @param[in] hash_alg	The numeric ID of the hashing algorithm to use. See @b cryptx_hash_algorithms.
 *  @return @b true if initialized succeeded, @b false if failed.
 *  @note Uses 516 bytes of fastMem starting at 0xE30800.
 */
bool cryptx_hmac_init(struct cryptx_hmac_ctx* context, const void* key, size_t keylen, uint8_t hash_alg);

/*********************************************************
 *	@brief Updates the hash-state for a given block of data.
 *	@param[in] context	Pointer to an HMAC-state context.
 *	@param[in] data		Pointer to a block of data to hash..
 *	@param[in] len		Size of the @b data to hash.
 *	@note Uses 516 bytes of fastMem starting at 0xE30800.
 *	@warning Calling this on a context that has not been initialized may have
 *	unpredictable results.
 */
void cryptx_hmac_update(struct cryptx_hmac_ctx* context, const void* data, size_t len);

/*****************************************************
 *	@brief Output digest for current HMAC-state (preserves state).
 *	@param[in] context	Pointer to an HMAC-state context.
 *	@param[out]	digest	Pointer to a buffer to write digest to.
 *	@note @b digest must be at large enough to hold the hash digest.
 *	You can retrieve the necessary size by accessing the @b digest_len
 *	member of an initialized @b cryptx_hmac_ctx.
 *	@note Uses 516 bytes of fastMem starting at 0xE30800.
 *  @warning Calling this on a context that has not been initialized may have
 *	unpredictable results.
 */
void cryptx_hmac_final(struct cryptx_hmac_ctx* context, void* output);

/****************************************************
 * @brief Derives a key from a password, salt, and round count.
 * @param[in] password 	Pointer to a string containing the password.
 * @param[in] passlen	Byte length of the password.
 * @param[out] key		Pointer to buffer to write key to.
 * @param[in] keylen	Length of @b key to generate.
 * @param[in] salt	 A psuedo-random string to use in each round of key derivation.
 * @param[in] saltlen	Byte length of the salt.
 * @param[in] rounds 	The number of times to iterate the HMAC function per block of @b keylen.
 * @param[in] hash_alg 	The numeric ID of the hashing algorithm to use. See @b cryptx_hash_algorithms.
 * @note NIST recommends a salt of at least 128 bits (16 bytes).
 * @note @b rounds is used to increase the cost (computational time) of generating a key. What makes password-
 * hashing algorithms secure is the time needed to generate a rainbow table attack against it. More rounds means
 * a more secure key, but more time spent generating it. Current cryptography standards recommend thousands of
 * rounds but that may not be feasible on the CE.
 */
bool cryptx_hmac_pbkdf2(
    const char* password,
    size_t passlen,
    void* key,
    size_t keylen,
    const void* salt,
    size_t saltlen,
    size_t rounds,
    uint8_t hash_alg);
    

//******************************************************************************************
/*	Digest Functions
 
	These functions perform tasks related to the digests output by the hash and HMAC
	API above. */

/*********************************************
 * @brief Convert a digest to its hexstring representation.
 * @param[in] digest	Pointer to a buffer or digest.
 * @param[in] len		Byte length of @b digest.
 * @param[out] hexstr	Buffer to write the output hex string to.
 * @note @b hexstr must be at least twice @b len +1 bytes large.
 */
bool cryptx_digest_tostring(const void* digest, size_t len, uint8_t* hexstr);


/*********************************************
 * @brief Compare two digests or buffers.
 * @param[in] digest1	Pointer to first buffer to compare.
 * @param[in] digest2	Pointer to second buffer to compare.
 * @param[in] len		Number of bytes to compare.
 * @return @b true if the buffers are equal, @b false if not equal.
 * @note This is a constant-time implementation.
 */
bool cryptx_digest_compare(const void* digest1, const void* digest2, size_t len);


#endif
