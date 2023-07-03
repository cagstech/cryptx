/**
 * @file cryptx.h
 * @brief Industry-Standard Cryptography for the TI-84+ CE
 * @author Anthony @e ACagliano Cagliano
 */

#ifndef cryptx_h
#define cryptx_h

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/// ### PRIVATE STRUCTS/INTERNAL USE ONLY -- DO NOT MODIFY ###
struct cryptx_priv_hash_sha256_state {
	uint8_t data[64];		/**< holds sha-256 block for transformation */
	uint8_t datalen;		/**< holds the current length of data in data[64] */
	uint8_t bitlen[8];		/**< holds the current length of transformed data */
	uint32_t state[8];		/**< holds hash state for transformed data */
};
typedef union {
	struct cryptx_priv_hash_sha256_state sha256;
} cryptx_hash_private_h;

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

struct cryptx_aes_cbc_state { uint8_t padding_mode; };
struct cryptx_aes_ctr_state {
	uint8_t counter_pos_start; uint8_t counter_len;
	uint8_t last_block_stop; uint8_t last_block[16]; };
struct cryptx_aes_gcm_state {
	uint8_t last_block_stop; uint8_t last_block[16];
	uint8_t ghash_key[16];
	uint8_t aad_cache[16]; uint8_t auth_tag[16]; uint8_t auth_j0[16];
	uint8_t aad_cache_len; size_t aad_len; size_t ct_len;
	uint8_t gcm_op;
};

typedef union {
	struct cryptx_aes_gcm_state gcm;					/**< metadata for GCM mode */
	struct cryptx_aes_cbc_state ctr;                    /**< metadata for counter mode */
	struct cryptx_aes_ctr_state cbc;                    /**< metadata for cbc mode */
} cryptx_aes_private_h;


/// ### CRYPTOGRAPHIC HASHING -- Use to verify data integrity ###
///
/// @struct Hash-State context
struct cryptx_hash_ctx {
	bool (*init)(void* ctx);
	void (*update)(void* ctx, const void* data, size_t len);
	void (*digest)(void* ctx, void* output);
	uint8_t digest_len;
	cryptx_hash_private_h metadata;
};

/// @enum Supported hash algorithms
enum cryptx_hash_algorithms {
	SHA256,             /**< algorithm type identifier for SHA-256 */
};

/**
 *	@brief Initializes a hash-state context for a specific hash algorithm.
 *	@param context	Pointer to a hash-state context.
 *  @param hash_alg	The numeric ID of the hashing algorithm to use. See @b cryptx_hash_algorithms.
 *  @return @b true if hash initialization succeeded, @b false if failed.
 *  @note Destroys 516 bytes of fastMem starting at 0xE30800.
 */
bool cryptx_hash_init(struct cryptx_hash_ctx* context, uint8_t hash_alg);

/**
 *	@brief Updates the hash-state for a given block of data.
 *	@param context	Pointer to a hash-state context.
 *	@param data		Pointer to a block of data to hash..
 *	@param len		Size of the @b data to hash.
 *	@note Destroys 516 bytes of fastMem starting at 0xE30800.
 *	@warning Calling this on a context that has not been initialized may have
 *	unpredictable results.
 */
void cryptx_hash_update(struct cryptx_hash_ctx* context, const void* data, size_t len);

/**
 *	@brief Output digest for current hash-state (preserves state).
 *	@param context	Pointer to a hash-state context.
 *	@param	digest	Pointer to a buffer to write digest to.
 *	@note @b digest must be at large enough to hold the hash digest.
 *	You can retrieve the necessary size by accessing the @b digest_len
 *	member of an initialized @b cryptx_hash_ctx.
 *	@note Destroys 516 bytes of fastMem starting at 0xE30800.
 *  @warning Calling this on a context that has not been initialized may have
 *	unpredictable results.
 */
void cryptx_hash_digest(struct cryptx_hash_ctx* context, void* digest);

/**
 *	@brief Computes a digest of arbitrary length for a given block of data.
 *	@param	data	Pointer to data to hash.
 *	@param	datalen	Size of @b data to hash.
 *	@param outbuf	Pointer to buffer to write digest to.
 *	@param	outlen 	Number of bytes to write to @b outbuf.
 *  @param	hash_alg	The numeric ID of the hashing algorithm to use. See @b cryptx_hash_algorithms.
 *	@note @b outbuf must be at least @b outlen bytes large.
 *	@note Destroys 516 bytes of fastMem starting at 0xE30800.
 */
void cryptx_hash_mgf1(const void* data,
					  size_t datalen,
					  void* outbuf,
					  size_t outlen,
					  uint8_t hash_alg);


/// ### HASH-BASED MESSAGE AUTHENTICATION CODE (HMAC) -- Use to verify data integrity and authenticity. ###

/// @struct HMAC-state context
struct cryptx_hmac_ctx {
	bool (*init)(void* ctx, const void* key, size_t keylen);
	void (*update)(void* ctx, const void* data, size_t len);
	void (*digest)(void* ctx, void* output);
	uint8_t digest_len;
	cryptx_hmac_private_h metadata;
};

/**
 *	@brief Initializes an HMAC-state context for a specific hash algorithm.
 *	@param context	Pointer to an HMAC-state context.
 *	@param key		Pointer to a key used to initialize the HMAC state.
 *	@param keylen	Length of the @b key.
 *  @param hash_alg	The numeric ID of the hashing algorithm to use. See @b cryptx_hash_algorithms.
 *  @return @b true if initialized succeeded, @b false if failed.
 *  @note Destroys 516 bytes of fastMem starting at 0xE30800.
 */
bool cryptx_hmac_init(struct cryptx_hmac_ctx* context,
					  const void* key, size_t keylen,
					  uint8_t hash_alg);

/**
 *	@brief Updates the hash-state for a given block of data.
 *	@param context	Pointer to an HMAC-state context.
 *	@param data		Pointer to a block of data to hash..
 *	@param len		Size of the @b data to hash.
 *	@note Destroys 516 bytes of fastMem starting at 0xE30800.
 *	@warning Calling this on a context that has not been initialized may have
 *	unpredictable results.
 */
void cryptx_hmac_update(struct cryptx_hmac_ctx* context, const void* data, size_t len);

/******************************************************
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
void cryptx_hmac_digest(struct cryptx_hmac_ctx* context, void* output);


//***************************************************************************************
//	PASSWORD-BASED KEY DERIVATION FUNCTION 2 (PBKDF2)
//***************************************************************************************
/** Use when you want to generate a secure key (eg: for encryption) from a password. */

/******************************************************
 * @brief Derives a key from a password, salt, and round count.
 * @param[in] password 	Pointer to a string containing the password.
 * @param[in] passlen	Byte length of the password.
 * @param[in] salt	 A psuedo-random string to use in each round of key derivation.
 * @param[in] saltlen	Byte length of the salt.
 * @param[in] rounds 	The number of times to iterate the HMAC function per block of @b keylen.
 * @param[out] key		Pointer to buffer to write key to.
 * @param[in] keylen	Length of @b key to generate.
 * @param[in] hash_alg 	The numeric ID of the hashing algorithm to use. See @b cryptx_hash_algorithms.
 * @note NIST recommends a salt of at least 128 bits (16 bytes).
 * @note @b rounds is used to increase the cost (computational time) of generating a key. What makes password-
 * hashing algorithms secure is the time needed to generate a rainbow table attack against it. More rounds means
 * a more secure key, but more time spent generating it. Current cryptography standards recommend thousands of
 * rounds but that may not be feasible on the CE.
 */
void cryptx_hmac_pbkdf2(const char* password,
						size_t passlen,
						const void* salt,
						size_t saltlen,
						uint8_t* key,
						size_t keylen,
						size_t rounds,
						uint8_t hash_alg);


//***************************************************************************************
//	DIGEST OPERATIONS
//***************************************************************************************
/** Use when you need to compare or render digests. */

/******************************************************
 * @brief Convert a digest to its hexstring representation.
 * @param[in] digest	Pointer to a buffer or digest.
 * @param[in] len		Byte length of @b digest.
 * @param[out] hexstr	Buffer to write the output hex string to.
 * @note @b hexstr must be at least twice @b len +1 bytes large.
 */
bool cryptx_digest_tostring(const void* digest, size_t len, uint8_t* hexstr);

/******************************************************
 * @brief Compare two digests or buffers.
 * @param[in] digest1	Pointer to first buffer to compare.
 * @param[in] digest2	Pointer to second buffer to compare.
 * @param[in] len		Number of bytes to compare.
 * @return @b true if the buffers are equal, @b false if not equal.
 * @note This is a constant-time implementation.
 */
bool cryptx_digest_compare(const void* digest1, const void* digest2, size_t len);


//***************************************************************************************
//	CRYPTOGRAPHICALLY-SECURE RANDOM NUMBER GENERATION
//***************************************************************************************
/** Use when you need to generate cryptographically-secure randomness (eg: keys, salts). */

/******************************************************
 * @brief Initializes the (HW)RNG.
 * @returns @b true on success, @b false on failure.
 * @note If you forget to call this function, utilizing the RNG's other functions will self-initialize the RNG.
 */
bool cryptx_csrand_init(void);

/******************************************************
 * @brief Returns a securely psuedo-random 32-bit integer
 * @returns A securely psuedo-random 32-bit integer.
 */
uint32_t cryptx_csrand_get(void);

/******************************************************
 * @brief Fills a buffer with securely pseduo-random bytes
 * @param[in] buffer	Pointer to a buffer to fill with random bytes.
 * @param[in] size		Size of the buffer to fill.
 * @returns @b true on success, @b false on failure.
 * @returns @b buffer filled to size.
 */
bool cryptx_csrand_fill(void* buffer, size_t size);


//***************************************************************************************
//	ADVANCED ENCRYPTION STANDARD (AES) ENCRYPTION
//***************************************************************************************
/** Use when you need fast bi-directional encryption. */

struct cryptx_aes_ctx {
	uint24_t keysize;                       /**< the size of the key, in bits */
	uint32_t round_keys[60];                /**< round keys */
	uint8_t iv[16];                         /**< IV state for next block */
	uint8_t ciphermode;                     /**< selected operational mode of the cipher */
	uint8_t op_assoc;                       /**< state-flag indicating if context is for encryption or decryption*/
	cryptx_aes_private_h metadata;			/**< opague, internal context metadata */
};

enum cryptx_aes_cipher_modes {
	AES_MODE_CBC,       /**< selects Cyclic Block Chain (CBC) mode */
	AES_MODE_CTR,       /**< selects Counter (CTR) mode */
	AES_MODE_GCM		/**< selects Galois Counter (GCM) mode */
};

enum cryptx_aes_padding_schemes {
	PAD_PKCS7,                  /**< PKCS#7 padding | DEFAULT */
	PAD_DEFAULT = PAD_PKCS7,	/**< selects the scheme marked DEFAULT.
								 Using this is recommended in case a change to the standards
								 would set a stronger padding scheme as default */
	PAD_ISO2					/**< ISO-9797 M2 padding */
};

#define CRYPTX_AES128_KEYLEN	16		/** Defines the byte length of an AES-128 key. */
#define CRYPTX_AES192_KEYLEN	24		/** Defines the byte length of an AES-192 key. */
#define CRYPTX_AES256_KEYLEN	32		/** Defines the byte length of an AES-256 key. */

#define CRYPTX_AES_BLOCK_SIZE	16		/** Defines the block size of the AES block, in bytes. */
#define CRYPTX_AES_IV_SIZE	CRYPTX_AES_BLOCK_SIZE	/** Defines the length of the AES initialization vector. */
#define CRYPTX_AES_AUTHTAG_SIZE	CRYPTX_AES_BLOCK_SIZE	/** Defines the length of the AES-GCM auth tag. */

/** Defines a macro to enable AES CBC cipher mode and pass relevant configuration options.*/
#define CRYPTX_AES_CBC_FLAGS(padding_mode) \
	((padding_mode)<<2) | AES_MODE_CBC

/** Defines a macro to enable AES CTR cipher mode and pass relevant configuration options.*/
#define CRYPTX_AES_CTR_FLAGS(nonce_len, counter_len)	\
	((0x0f & (counter_len))<<8) | ((0x0f & (nonce_len))<<4) | AES_MODE_CTR

/** Defines a macro to enable AES GCM cipher mode.*/
#define CRYPTX_AES_GCM_FLAGS	AES_MODE_GCM

/** Defines a macro to return the byte length of an AES ciphertext given a plaintext length.*/
#define cryptx_aes_get_ciphertext_len(len) \
((((len)%CRYPTX_AES_BLOCK_SIZE)==0) ? (len) + CRYPTX_AES_BLOCK_SIZE : (((len)>>4) + 1)<<4)

typedef enum {
	AES_OK,                             /**< AES operation completed successfully */
	AES_INVALID_ARG,                    /**< AES operation failed, bad argument */
	AES_INVALID_MSG,                    /**< AES operation failed, message invalid */
	AES_INVALID_CIPHERMODE,             /**< AES operation failed, cipher mode undefined */
	AES_INVALID_PADDINGMODE,            /**< AES operation failed, padding mode undefined */
	AES_INVALID_CIPHERTEXT,             /**< AES operation failed, ciphertext error */
	AES_INVALID_OPERATION               /**< AES operation failed, used encrypt context for decrypt or vice versa */
} aes_error_t;

/******************************************************
 * @brief Initializes a stateful AES cipher context to be used for encryption or decryption.
 * @param[in] context	Pointer to an AES cipher context to initialize.
 * @param[in] key	Pointer to an 128, 192, or 256 bit key to load into the AES context.
 * @param[in] keylen	The size, in bytes, of the @b key to load.
 * @param[in] iv	Pointer to  Initialization vector, a buffer equal to the block size filled with random bytes.
 * @param[in] ivlen	Length of the initalization vector. Capped at 16 bytes. Certain cipher modes have different recommendations.
 * @param[in] flags	A series of flags to configure the AES context with.
 * 				Use the provided @b CRYPTX_AES_CTR_FLAGS, @b CRYPTX_AES_CBC_FLAGS, or @b CRYPTX_AES_GCM_FLAGS to pass flags.
 * @returns An @b aes_error_t indicating the status of the AES operation.
 * @note Contexts are not bidirectional due to being stateful. If you need to process both encryption and decryption,
 * initialize seperate contexts for encryption and decryption. Both contexts will use the same key, but different initialization vectors.
 * @warning It is recommended to cycle your key after encrypting 2^64 blocks of data with the same key.
 * @warning Do not manually edit the @b ctx.mode field of the context structure.
 * This will break the cipher configuration. If you want to change cipher modes, do so by calling @b aes_init again.
 * @warning AES-CBC and CTR modes ensure confidentiality but do not provide message integrity verification.
 * If you need a truly secure construction, use GCM mode or append a keyed hash (HMAC) to the encrypted message..
 */
aes_error_t cryptx_aes_init(struct cryptx_aes_ctx* context,
							const void* key,
							size_t keylen,
							const void* iv,
							size_t ivlen,
							uint24_t flags);

/******************************************************
 * @brief Performs a stateful AES encryption of an arbitrary length of data.
 * @param[in] context	Pointer to an AES cipher context.
 * @param[in] plaintext	Pointer to data to encrypt.
 * @param[in] len		Length of data at @b plaintext to encrypt.
 * @param[out] ciphertext	Pointer to buffer to write encrypted data to.
 * @returns An @b aes_error_t indicating the status of the AES operation.
 * @note @b ciphertext should large enough to hold the encrypted message.
 *          For CBC mode, this is the smallest multiple of the blocksize that will hold the plaintext.
 *          See the @b CRYPTX_AES_CIPHERTEXT_LEN macro.
 *          For CTR and GCM modes, this is the same size as the plaintext.
 * @note @b plaintext and @b ciphertext are aliasable.
 * @note Encrypt is streamable, such that encrypt(msg1) + encrypt(msg2) is functionally identical to encrypt(msg1+msg2)
 * with the exception of intervening padding in CBC mode.
 * @note Once a  context is used for encryption, it cannot be used for decryption.
 */
aes_error_t cryptx_aes_encrypt(const struct cryptx_aes_ctx* context,
							   const void* plaintext,
							   size_t len,
							   void* ciphertext);

/******************************************************
 * @brief Performs a stateful AES decryption of an arbitrary length of data.
 * @param[in] context		Pointer to AES cipher context.
 * @param[in] ciphertext	Pointer to data to decrypt.
 * @param[in] len		Length of data at @b ciphertext to decrypt.
 * @param[out] plaintext	Pointer to buffer to write decryped data to.
 * @returns An @b aes_error_t indicating the status of the AES operation.
 * @note @b plaintext and @b ciphertext are aliasable.
 * @note Decrypt is streamable, such that decrypt(msg1) + decrypt(msg2) is functionally identical to decrypt(msg1+msg2)
 * with the exception of intervening padding in CBC mode.
 * @note Once a context is used for decryption, it cannot be used for encryption.
 */
aes_error_t cryptx_aes_decrypt(const struct cryptx_aes_ctx* context,
							   const void* ciphertext,
							   size_t len,
							   void* plaintext);

/******************************************************
 * @brief Updates the cipher context for given AAD (Additional Authenticated Data).
 * AAD is data that is only authenticated, not encrypted.
 * @param[in] context	Pointer to an AES context.
 * @param[in] aad		Pointer to additional authenticated data segment.
 * @param[in] aad_len	Length of additional data segment.
 * @returns An @b aes_error_t indicating the status of the AES operation.
 * @note This function is only compatible with AES-GCM cipher mode. Attempting to
 * use this function for any other cipher mode will return @b AES_INVALID_CIPHERMODE.
 * @note This function can only be called between the call to @b cryptx_aes_init and the first call
 * to @b cryptx_aes_encrypt or @b cryptx_aes_decrypt. Once encryption or decryption starts, you can
 * no longer update AAD.
 */
aes_error_t cryptx_aes_update_aad(struct cryptx_aes_ctx* context,
								  const void* aad, size_t aad_len);

/******************************************************
 * @brief Returns the current authentication tag for data parsed so far.
 * @param[in] context	Pointer to an AES context
 * @param[out] digest	Pointer to a buffer to output digest to. Must be at least 16 bytes large.
 * @returns An @b aes_error_t indicating the status of the AES operation.
 * @note This function is only compatible with AES-GCM cipher mode. Attempting to call it for any
 * other cipher mode will return @b AES_INVALID_CIPHERMODE.
 * @note Calling this function terminates your use of the current AES context. This is because
 * reuse of the IV buffer can leak the hkey used for authentication. The next stream may use the same
 * encryption key but should have a unique IV.
 */
aes_error_t cryptx_aes_digest(struct cryptx_aes_ctx* context, uint8_t *digest);

/******************************************************
 * @brief Parses the specified AAD and ciphertext and then compares the output auth tag
 * to an expected auth tag.
 * @param[in] context	Pointer to an AES context.
 * @param[in] aad		Pointer to associated data to authenticate.
 * @param[in] aad_len	Length of associated data to authenticate.
 * @param[in] ciphertext	Pointer to ciphertext to authenticate.
 * @param[in] ciphertext_len	Length of ciphertext to authenticate.
 * @param[in] tag		Pointer to expected auth tag to validate against.
 * @returns TRUE if authentication  tag matches expected, FALSE otherwise.
 * @note operates on a dummy copy of @b *context to avoid nuking the active copy
 * @note If this function returns FALSE, do not decrypt the message.
 */

bool cryptx_aes_verify(const struct cryptx_aes_ctx* context,
					   const void* aad, size_t aad_len,
					   const void* ciphertext, size_t ciphertext_len,
					   uint8_t *tag);


//***************************************************************************************
//	RIVEST-SHAMIR-ADLEMAN (RSA) ENCRYPTION
//***************************************************************************************
/** Use when you need to encrypt a secret (eg: for AES) in order to create a secure session. */

typedef enum {
	RSA_OK,                         /**< RSA encryption completed successfully */
	RSA_INVALID_ARG,                /**< RSA encryption failed, bad argument */
	RSA_INVALID_MSG,                /**< RSA encryption failed, bad msg or msg too long */
	RSA_INVALID_MODULUS,            /**< RSA encryption failed, modulus invalid */
	RSA_ENCODING_ERROR              /**< RSA encryption failed, OAEP encoding error */
} rsa_error_t;

/** Defines the maximum byte length of an RSA public modulus supported by this library. */
#define CRYPTX_RSA_MODULUS_MAX		256

/******************************************************
 * @brief Encrypts a message using the given RSA public key.
 * @param[in] msg	Pointer to a message to encrypt using RSA.
 * @param[in] msglen	The byte length of the @b msg.
 * @param[in] pubkey	Pointer to a public key to use for encryption.
 * @param[in] keylen	The length of the public key (modulus) to encrypt with.
 * @param[out] ciphertext 	Pointer a buffer to write the ciphertext to.
 * @param[in] oaep_hash_alg	The numeric ID of the hashing algorithm to use within OAEP encoding.
 *      See @b cryptx_hash_algorithms.
 * @returns  An @b rsa_error_t indicating the status of the RSA operation.
 * @note The size of @b ciphertext and @b keylen must be equal.
 * @note The @b msg will be encoded using OAEP before encryption.
 * @note msg and pubkey are both treated as byte arrays.
 * @note The public exponent is hardcoded to @b 65537.
 */
rsa_error_t cryptx_rsa_encrypt(const void* msg,
							   size_t msglen,
							   const void* pubkey,
							   size_t keylen,
							   void* ciphertext,
							   uint8_t oaep_hash_alg);


//***************************************************************************************
//	ELLIPTIC CURVE DIFFIE-HELLMAN (ECDH) ENCRYPTION
//***************************************************************************************
/** An alternate form of secret (for AES) negotiation. */
// Using curve SECT233k1

/** Defines the byte length of an ECDH private key supported by this library. */
#define CRYPTX_ECDH_PRIVKEY_LEN		30

/** Defines the byte length of an ECDH public key supported by this library.  */
#define CRYPTX_ECDH_PUBKEY_LEN		(CRYPTX_ECDH_PRIVKEY_LEN<<1)
#define CRYPTX_ECDH_SECRET_LEN		CRYPTX_ECDH_PUBKEY_LEN

#define	cryptx_ecdh_generate_privkey(privkey)	\
	cryptx_csrand_fill((privkey), (CRYPTX_ECDH_PRIVKEY_LEN))

typedef enum _ecdh_error {
	ECDH_OK,
	ECDH_INVALID_ARG,
	ECDH_PRIVKEY_INVALID,
	ECDH_RPUBKEY_INVALID
} ecdh_error_t;

/******************************************************
 * @brief Generates a public key from the private key and some base point G on curve.
 * @param[in] privkey	Pointer to a randomized ECDH private key.
 * @param[out] pubkey	Pointer to buffer to write public key.
 * @note Output public key is a point on the curve expressed as two 30-byte coordinates
 * encoded in little endian byte order and padded with zeros (if needed). You may have to
 * deserialize the key and then serialize it into a different format to use it with
 * some encryption libraries.
 * @note This function expects that @b privkey be filled with random bytes. Failure to do so
 * may cause unexpected behavior. See @b CRYPTX_ECDH_GENERATE_PRIVKEY().
 */
ecdh_error_t cryptx_ecdh_publickey(const uint8_t *privkey, uint8_t *pubkey);

/******************************************************
 * @brief Computes a secret from the private key and the remote public key.
 * @param[in] privkey	Pointer to local private key.
 * @param[in] rpubkey	Pointer to remote public key.
 * @param[out] secret	Pointer to buffer to write shared secret to.
 * @note @b secret must be at least @b CRYPTX_ECDH_SECRET_LEN bytes.
 * @note Output secret is a point on the curve expressed as two 30-byte coordinates
 * encoded in little endian byte order and padded with zeros if needed. You may have to
 * deserialize the secret and then serialize it into a different format for compatibility with
 * other encryption libraries.
 * @note It is generally not recommended to use the computed secret as an encryption key as is.
 * It is preferred to pass the secret to a KDF or a cryptographic primitive such as a hash function and use
 * that output as your symmetric key.
 */
ecdh_error_t cryptx_ecdh_secret(const uint8_t *privkey, const uint8_t *rpubkey, uint8_t *secret);

//***************************************************************************************
//	ABSTRACT SYNTAX NOTATION ONE (ASN.1) DECODING
//***************************************************************************************
/** Used to decode ASN.1-encoded data structures, such as those output by most encryption libraries. */

enum CRYPTX_ASN1_TAGS {
	ASN1_RESVD = 0,				/**< RESERVED */
	ASN1_BOOLEAN,				/**< defines a BOOLEAN object */
	ASN1_INTEGER,				/**< defines an INTEGER object */
	ASN1_BITSTRING,				/**< defines a BIT STRING object */
	ASN1_OCTETSTRING,			/**< defines an OCTET STRING object */
	ASN1_NULL,					/**< defines a NULL object (0 size, no data) */
	ASN1_OBJECTID,				/**< defines an OBJECT IDENTIFIER */
	ASN1_OBJECTDESC,			/**< defines an OBJECT DESCRIPTION */
	ASN1_INSTANCE,				/**< defines an INSTANCE */
	ASN1_REAL,					/**< defines a REAL object */
	ASN1_ENUMERATED,
	ASN1_EMBEDDEDPDV,
	ASN1_UTF8STRING,
	ASN1_RELATIVEOID,
	ASN1_SEQUENCE = 16,			/**< defines a SEQUENCE */
	ASN1_SET,					/**< defines a SET */
	ASN1_NUMERICSTRING,
	ASN1_PRINTABLESTRING,
	ASN1_TELETEXSTRING,
	ASN1_VIDEOTEXSTRING,
	ASN1_IA5STRING,
	ASN1_UTCTIME,
	ASN1_GENERALIZEDTIME,
	ASN1_GRAPHICSTRING,
	ASN1_VISIBLESTRING,
	ASN1_GENERALSTRING,
	ASN1_UNIVERSALSTRING,
	ASN1_CHARSTRING,
	ASN1_BMPSTRING
};

enum CRYPTX_ASN1_CLASSES {
	ASN1_UNIVERSAL,			/**< tags defined in the ASN.1 standard. Most use cases on calc will be this. */
	ASN1_APPLICATION,		/**< tags unique to a particular application. */
	ASN1_CONTEXTSPEC,		/**< tags that need to be identified within a particular, well-definded context. */
	ASN1_PRIVATE			/**< reserved for use by a specific entity for their applications. */
};

enum CRYPTX_ASN1_FORMS {
	ASN1_PRIMITIVE,			/**< this element should contain no nested elements. */
	ASN1_CONSTRUCTED,		/**< this element contains nested elements. */
};

/// Returns the unmasked tag. See @b CRYPTX_ASN1_TAGS above.
#define cryptx_asn1_get_tag(tag)		((tag) & 0b111111)
/// Returns the 2-bit tag class flag. See @b CRYPTX_ASN1_CLASSES above.
#define cryptx_asn1_get_class(tag)		(((tag)>>6) & 0b11)
/// Returns the 1-bit tag form (1 = constructed, 0 = primitive). See @b CRYPTX_ASN1_FORMS above.
#define cryptx_asn1_get_form(tag)		(((tag)>>5) & 1)

typedef enum {
	ASN1_OK,				/**< No errors occured. */
	ASN1_END_OF_FILE,		/**< End of ASN.1 data stream reached. Not an error. */
	ASN1_INVALID_ARG,		/**< One or more arguments invalid. */
	ASN1_LEN_OVERFLOW,		/**< Length of an element overflowed arch size\_t allowance. Remainder of data stream unparsable. */
} asn1_error_t;

/******************************************************
 * @brief Decodes the ASN.1 data at the given address. Seeks to an element from the front of the data.
 * @param data_start	Pointer to a block of ASN.1-encoded data.
 * @param data_len		Length of ASN.1-encoded block.
 * @param seek_to		Number of ASN.1 elements to skip before returning one.
 * @param element_tag	Masked tag value of the returned element.
 * @param element_len	Length of the returned element.
 * @param element_data	Pointer to the data of the returned element.
 * @returns				An @b asn1_error_t indicating the status of the operation.
 * @note @b ASN1_END_OF_FILE will be returned if @b seek_to is invalid.
 * @note ASN.1 is a tree structure. You can use the @b element_data and @b element_len parameters
 * returned by this function to iterate further up the tree. To see if an element is of a type for which this is
 * valid, check the return value of @b CRYPTX_ASN1_FORM(element_tag).
 * @note NULL may be passed for @b element_tag, @b element_len, and/or @b element_data if you do not
 * need to return that particular bit of information.
 */
asn1_error_t cryptx_asn1_decode(
					void *data_start,
					size_t data_len,
					uint8_t seek_to,
					uint8_t *element_tag,
					size_t *element_len,
					uint8_t **element_data);


//***************************************************************************************
//	BASE64 DECODING
//***************************************************************************************
/** Used to encode to or decode from Base64, another encoding format common to cryptography libraries. */

#define	cryptx_base64_get_encoded_len(len)		((len) * 4 / 3)
#define	cryptx_base64_get_decoded_len(len)		((len) * 3 / 4)

/******************************************************
 * @brief Converts an octet-encoded byte stream into a sextet-encoded byte stream.
 * @param dest Pointer to output sextet-encoded data stream.
 * @param src Pointer to input octet-encoded data stream.
 * @param len Length of octet-encoded data stream.
 * @note @b dest should be at least  @b len \* 4 / 3 bytes large.
 * @returns Length of output sextet.
 */
size_t cryptx_base64_encode(void *dest, const void *src, size_t len);

/******************************************************
 * @brief Converts a sextet-encoded byte stream into a octet-encoded byte stream.
 * @param dest Pointer to output octet-encoded data stream.
 * @param src Pointer to input sextet-encoded data stream.
 * @param len Length of sextet-encoded data stream.
 * @note @b dest should be at least @b len \* 3 / 4 bytes large.
 * @returns Length of output octet.
 */
size_t cryptx_base64_decode(void *dest, const void *src, size_t len);


#ifdef CRYPTX_ENABLE_HAZMAT

/** AES-ECB mode single block encryption */
void cryptx_hazmat_aes_ecb_encrypt(const void *block_in,
									 void *block_out,
									 struct cryptx_aes_ctx* ks);

/** AES-ECB mode single block decryption */
void cryptx_hazmat_aes_ecb_decrypt(const void *block_in,
									 void *block_out,
									 struct cryptx_aes_ctx* ks);

/** RSA-OAEP encoding */
bool cryptx_hazmat_rsa_oaep_encode(const void *plaintext,		/**< input */
									 size_t len,
									 void *encoded,				/**< output */
									 size_t modulus_len,
									 const uint8_t *auth,
									 uint8_t hash_alg);

/** RSA-OAEP decoding */
bool cryptx_hazmat_rsa_oaep_decode(const void *encoded,		/**< input */
									 size_t len,
									 void *plaintext,			/**< output */
									 const uint8_t *auth,
									 uint8_t hash_alg);

/** RSAEP modular exponentiation subfunction (by jacobly) */
void cryptx_hazmat_powmod(uint8_t size,					/**< modulus bytelen */
							uint8_t *restrict base,			/**< base */
							uint24_t exp,					/**< exponent */
							const uint8_t *restrict mod);	/**< modulus */

struct cryptx_ecc_point {
	uint8_t x[GF2_INTLEN];
	uint8_t y[GF2_INTLEN];
}

/** Elliptic Curve point addition over SECT233K1 */
void cryptx_hazmat_ecc_point_add(cryptx_ecc_point* p, cryptx_ecc_point* q);

/** Elliptic Curve point doubling over SECT233K1 */
void cryptx_hazmat_ecc_point_double(cryptx_ecc_point* p);

/** Elliptic Curve scalar multiplication over SECT233K1 */
void cryptx_hazmat_ecc_point_mul_scalar(cryptx_ecc_point* p,
										  const uint8_t* scalar,
										  size_t scalar_bit_width);

#endif

#endif
