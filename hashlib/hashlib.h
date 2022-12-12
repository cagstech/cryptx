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

/**********************************************
 * @def fastRam_Safe
 * Pointer to a region of fast RAM that is generally safe to use
 * as long as you don't call Libload.
 */
#define fastRam_Safe		((void*)0xE30A04)
 
 /*********************************************
  * @def fastRam_Unsafe
  *	Pointer to the start of the region of fast RAM, including the safe region above as well as
  *	a region used by the library's csrng.
  */
#define fastRam_Unsafe		((void*)0xE30800)
 
 
/*
Cryptographic Hashes
 
A cryptographic hash is used to validate that data is unchanged between two endpoints.
It is similar to a checksum, but checksums can be easily fooled; cryptographic hashes
are a lot harder to fool due to how they distribute the bits in a data stream.
The general use of a hash is as follows: the party sending a message hashes it and
includes that hash as part of the message. The recipient hashes the message (except the hash)
themselves and then compares that hash to the one included in the message. If the hashes match,
the message is complete and unaltered. If the hashes do not match, the message is incomplete
or has been tampered with.
*/

/**********************************************
 * @typedef sha256_ctx
 * Defines hash-state data for an instance of SHA-256.
 * This structure is internal. You should never need to use this.
 */
struct _hashlib_sha256 {
	uint8_t data[64];		/**< holds sha-256 block for transformation */
	uint8_t datalen;		/**< holds the current length of data in data[64] */
	uint8_t bitlen[8];		/**< holds the current length of transformed data */
	uint32_t state[8];		/**< holds hash state for transformed data */
};

/**************************************
 * @typedef hash_ctx
 * Defines universal hash-state data, including pointer to algorithm-specific handling methods and
 * a union of computational states for various hashes.
 */
struct cryptx_hash_ctx {
	bool (*init)(void* ctx);
	void (*update)(void* ctx, const void* data, size_t len);
	void (*final)(void* ctx, void* output);
	union {
		struct _hashlib_sha256 sha256;
	} _internal;
	uint8_t digest_len;
};
 
 /*******************************
  * @enum hash_algorithms
  * Idenitifiers for selecting hash types.
  */
enum cryptx_hash_algorithms {
    SHA256,             /**< algorithm type identifier for SHA-256 */
};

/*********************************
 * @def SHA256_DIGEST_LEN
 * Binary length of the SHA-256 hash output.
 */
#define SHA256_DIGEST_LEN   32

/**************************************************************
 *	@brief Hash initializer.
 *	Initializes the given context with the starting state for the given hash algorithm and
 *  populates pointers to the methods for update and final for the given hash..
 *	@param ctx Pointer to a hash context (hash_ctx).
 *  @param hash_alg The numeric ID of the hashing algorithm to use. See @b hash_algorithms.
 *  @return Boolean. True if hash initialization succeeded. False if hash ID invalid.
 */
bool cryptx_hash_init(struct cryptx_hash_ctx* context, uint8_t hash_alg);

/*********************************************************
 *	@brief Updates the hash context for the given data.
 *	@param ctx Pointer to a hash context.
 *	@param data Pointer to data to hash.
 *	@param len Number of bytes at @b data to hash.
 *  @note You can use @b ctx.update() as an alternative to this function.
 *      If doing so, you must pass @b &ctx.Hash instead of @b &ctx.
 *	@warning You must have an initialized hash context or a crash will ensue.
 */
void cryptx_hash_update(struct cryptx_hash_ctx* context, const void* data, size_t len);

/*****************************************************
 *	@brief Finalize context and render digest for hash
 *	@param ctx Pointer to a hash context.
 *	@param digest Pointer to a buffer to write the hash to.
 *	@note @b digest must be at large enough to hold the hash digest.
 *  @note You can use @b ctx.final() as an alternative to this function.
 *      If doing so, you must pass @b &ctx.Hash instead of @b &ctx.
 *  @warning You must have an initialized hash context or a crash will ensue.
 */
void cryptx_hash_final(struct cryptx_hash_ctx* context, void* digest);

/*************************************************
 *	@brief Arbitrary Length Hashing Function
 *
 *	Computes an arbitrary length hash from the given data using the given hashing algorithm.
 *
 *	@param data Pointer to data to hash.
 *	@param datalen Number of bytes at @b data to hash.
 *	@param outbuf Pointer to buffer to write hash output to.
 *	@param outlen Number of bytes to write to @b outbuf.
 *  @param hash_alg The numeric ID of the hashing algorithm to use. See @b hash_algorithms.
 *	@note @b outbuf must be at least @b outlen bytes large.
 */
bool cryptx_hash_mgf1(const void* data, size_t datalen, void* outbuf, size_t outlen, uint8_t hash_alg);


/*
Hash-Based Message Authentication Code (HMAC)

HMAC generates a more secure hash by using a key known only to authorized
parties as part of the hash initialization. Thus, while normal hashes can be
verified by anyone, only the parties with the key can validate using a HMAC hash.
*/

/*******************************************
 * @typedef sha256hmac_ctx
 * Defines hash-state data for an instance of SHA-256.
 */
struct _cryptx_sha256hmac {
    uint8_t ipad[64];       /**< holds the key xored with a magic value to be hashed with the inner digest */
    uint8_t opad[64];       /**< holds the key xored with a magic value to be hashed with the outer digest */
    uint8_t data[64];		/**< holds sha-256 block for transformation */
	uint8_t datalen;		/**< holds the current length of data in data[64] */
	uint8_t bitlen[8];		/**< holds the current length of transformed data */
	uint32_t state[8];		/**< holds hash state for transformed data */
};

/*************************************
 * @typedef hmac_ctx
 * Defines hash-state data for an HMAC instance.
 */
struct cryptx_hmac_ctx {
    bool (*init)(void* ctx, const void* key, size_t keylen);
    void (*update)(void* ctx, const void* data, size_t len);
    void (*final)(void* ctx, void* output);
    union {
        struct _cryptx_sha256hmac sha256hmac;
    } _internal;
};

/*************************************************************
 *	@brief Context Initializer for HMAC
 *
 *	Initializes the given context with the starting state for the given HMAC algorithm.
 *
 *	@param ctx Pointer to a hmac context.
 *	@param key Pointer to an authentication key used to initialize the base hmac context.
 *	@param keylen Length of @b key, in bytes.
 *  @param hash_alg The numeric ID of the hashing algorithm to use. See @b hash_algorithms.
 *  @return Boolean. True if hash initialization succeeded. False if hash ID invalid.
 */
bool cryptx_hmac_init(struct cryptx_hmac_ctx* context, const void* key, size_t keylen, uint8_t hash_alg);

/*********************************************
 *	@brief Updates the hmac context for the given data.
 *	@param ctx Pointer to an HMAC context.
 *	@param data Pointer to data to hash.
 *	@param len Number of bytes at @b data to hash.
 *  @note You may use @b ctx.update() as an alternative to this function.
 *      If doing so, you must pass @b &ctx.Hmac instead of @b &ctx.
 *	@warning You must have an initialized hash context or a crash will ensue.
 */
void cryptx_hmac_update(struct cryptx_hmac_ctx* context, const void* data, size_t len);

/*************************************************
 *	@brief Finalize Context and Render Digest for HMAC
 *	@param ctx Pointer to an HMAC context.
 *	@param digest Pointer to a buffer to write the hash to.
 *	@note @b digest must be large enough to hold the hash digest.
 *  @note You may use @b ctx.final() as an alternative to this function.
 *      If doing so, you must pass @b &ctx.Hmac instead of @b &ctx.
 *  @warning You must have an initialized hash context or a crash will ensue.
 */
void cryptx_hmac_final(struct cryptx_hmac_ctx* context, void* output);

/*********************************************
 * @brief Password-Based Key Derivation Function
 *
 * Computes a key derived from a password, a 16-byte salt, and a given number of rounds.
 *
 * @param password Pointer to a string containing the password to derive a key from.
 * @param passlen The length of the password (in bytes).
 * @param key The buffer to write the key to. Must be at least @b keylen bytes large.
 * @param keylen The length of the key to generate (in bytes).
 * @param salt A psuedo-random string to use when computing the key.
 * @param saltlen The length of the salt to use (in bytes).
 * @param rounds The number of times to iterate the hash function per block of @b keylen.
 * @param hash_alg The numeric ID of the hashing algorithm to use. See @b hash_algorithms.
 * @note Standards recommend a salt of at least 128 bits (16 bytes).
 * @note @b rounds is used to increase the cost (computational time) of generating a key. What makes password-
 * hashing algorithms secure is the time needed to generate a rainbow table attack against it. More rounds means
 * a more secure key, but more time spent generating it. Current cryptography standards recommend in excess of 1000
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
    

// Miscellaneous Functions

/*********************************************
 * @brief Convert a digest to a valid hex string.
 * @param digest Pointer to a buffer or digest to convert.
 * @param len Number of bytes at @b digest to convert.
 * @param hexstr A buffer to write the output hex string to. Must be at least 2 * len + 1 bytes large.
 */
bool cryptx_digest_tostring(const void* digest, size_t len, char* hexstr);


/*********************************************
 * @brief Secure buffer comparison
 *
 * Evaluates the equality of two buffers using a method that offers resistance to timing attacks.
 *
 * @param digest1 The first buffer to compare.
 * @param digest2 The second buffer to compare.
 * @param len The number of bytes to compare.
 * @return True if the buffers were equal. False if not equal.
 */
bool cryptx_digest_compare(const void* digest1, const void* digest2, size_t len);


#endif
