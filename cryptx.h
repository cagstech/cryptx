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


/**
 @brief @b PRIVATE -- DO NOT MODIFY
 */
struct cryptx_priv_hash_sha256_state {
	uint8_t data[64];		/**< holds sha-256 block for transformation */
	uint8_t datalen;		/**< holds the current length of data in data[64] */
	uint8_t bitlen[8];		/**< holds the current length of transformed data */
	uint32_t state[8];		/**< holds hash state for transformed data */
};

/**
 @brief @b PRIVATE -- DO NOT MODIFY
 */
typedef union {
	struct cryptx_priv_hash_sha256_state sha256;
} cryptx_hash_private_h;

/**
 @brief @b PRIVATE -- DO NOT MODIFY
 */
struct cryptx_priv_hmac_sha256_state {
	uint8_t ipad[64];       /**< holds the key xored with a magic value to be hashed with the inner digest */
	uint8_t opad[64];       /**< holds the key xored with a magic value to be hashed with the outer digest */
	uint8_t data[64];		/**< holds sha-256 block for transformation */
	uint8_t datalen;		/**< holds the current length of data in data[64] */
	uint8_t bitlen[8];		/**< holds the current length of transformed data */
	uint32_t state[8];		/**< holds hash state for transformed data */
};

/**
 @brief @b PRIVATE -- DO NOT MODIFY
 */
typedef union {
	struct cryptx_priv_hmac_sha256_state sha256;
} cryptx_hmac_private_h;

/**
 @brief @b PRIVATE -- DO NOT MODIFY
 */
struct cryptx_aes_cbc_state { uint8_t padding_mode; };

/**
 @brief @b PRIVATE -- DO NOT MODIFY
 */
struct cryptx_aes_ctr_state {
	uint8_t counter_pos_start; uint8_t counter_len;
	uint8_t last_block_stop; uint8_t last_block[16]; };

/**
 @brief @b PRIVATE -- DO NOT MODIFY
 */
struct cryptx_aes_gcm_state {
	uint8_t last_block_stop; uint8_t last_block[16];
	uint8_t ghash_key[16];
	uint8_t aad_cache[16]; uint8_t auth_tag[16]; uint8_t auth_j0[16];
	uint8_t aad_cache_len; size_t aad_len; size_t ct_len;
	uint8_t gcm_op;
};

/**
 @brief @b PRIVATE -- DO NOT MODIFY
 */
typedef union {
	struct cryptx_aes_gcm_state gcm;					/**< metadata for GCM mode */
	struct cryptx_aes_cbc_state ctr;                    /**< metadata for counter mode */
	struct cryptx_aes_ctr_state cbc;                    /**< metadata for cbc mode */
} cryptx_aes_private_h;

/// @struct Hash-State context
struct cryptx_hash_ctx {
	bool (*init)(void* ctx);									/**< Pointer to function call for hash initialization */
	void (*update)(void* ctx, const void* data, size_t len);	/**< Pointer to function call for hash update */
	void (*digest)(void* ctx, void* output);					/**< Pointer to function call for digest output */
	uint8_t digest_len;										/**< Output length of hash digest, in bytes */
	cryptx_hash_private_h metadata;							/**< PRIVATE, INTERNAL */
};

/// @enum Supported hash algorithms
enum cryptx_hash_algorithms {
	SHA256,             /**< algorithm type identifier for SHA-256 */
	SHA1,               /**< algorithm type identifier for SHA-1 */
};


#define CRYPTX_DIGESTLEN_SHA1    20    /**< digest length for SHA-1 hash */
#define CRYPTX_DIGESTLEN_SHA256  32    /**< digest length for SHA-256 hash */

/**
 *	@brief Initializes a hash-state context for a specific hash algorithm.
 *	@param context	Pointer to a hash-state context.
 *  @param hash_alg	The numeric ID of the hashing algorithm to use. See @b cryptx_hash_algorithms.
 *  @return @b true if hash initialization succeeded, @b false if failed.
 */
bool cryptx_hash_init(struct cryptx_hash_ctx* context, uint8_t hash_alg);

/**
 *	@brief Updates the hash-state for a given block of data.
 *	@param context	Pointer to a hash-state context.
 *	@param data		Pointer to a block of data to hash..
 *	@param len		Size of the @b data to hash.
 */
void cryptx_hash_update(struct cryptx_hash_ctx* context, const void* data, size_t len);

/**
 *	@brief Output digest for current hash-state (preserves state).
 *	@param context	Pointer to a hash-state context.
 *	@param	digest	Pointer to a buffer to write digest to.
 */
void cryptx_hash_digest(struct cryptx_hash_ctx* context, void* digest);

/**
 *	@brief Computes a digest of arbitrary length for a given block of data.
 *	@param	data	Pointer to data to hash.
 *	@param	datalen	Size of @b data to hash.
 *	@param outbuf	Pointer to buffer to write digest to.
 *	@param	outlen 	Number of bytes to write to @b outbuf.
 *  @param	hash_alg	The numeric ID of the hashing algorithm to use. See @b cryptx_hash_algorithms.
 */
void cryptx_hash_mgf1(const void* data,
					  size_t datalen,
					  void* outbuf,
					  size_t outlen,
					  uint8_t hash_alg);


/// ### HASH-BASED MESSAGE AUTHENTICATION CODE (HMAC) -- Use to verify data integrity and authenticity. ###

/// @struct HMAC-state context
struct cryptx_hmac_ctx {
	bool (*init)(void* ctx, const void* key, size_t keylen);		/**< Pointer to function call for hmac initialization */
	void (*update)(void* ctx, const void* data, size_t len);		/**< Pointer to function call for hmac update */
	void (*digest)(void* ctx, void* output);						/**< Pointer to function call for hmac digest output */
	uint8_t digest_len;												/**< Length of output digest for hmac, in bytes */
	cryptx_hmac_private_h metadata;									/**< PRIVATE, INTERNAL */
};

/**
 *	@brief Initializes an HMAC-state context for a specific hash algorithm.
 *	@param context	Pointer to an HMAC-state context.
 *	@param key		Pointer to a key used to initialize the HMAC state.
 *	@param keylen	Length of the @b key.
 *  @param hash_alg	The numeric ID of the hashing algorithm to use. See @b cryptx_hash_algorithms.
 *  @return @b true if initialized succeeded, @b false if failed.
 */
bool cryptx_hmac_init(struct cryptx_hmac_ctx* context,
					  const void* key, size_t keylen,
					  uint8_t hash_alg);

/**
 *	@brief Updates the hash-state for a given block of data.
 *	@param context	Pointer to an HMAC-state context.
 *	@param data		Pointer to a block of data to hash..
 *	@param len		Size of the @b data to hash.
 */
void cryptx_hmac_update(struct cryptx_hmac_ctx* context, const void* data, size_t len);

/**
 *	@brief Output digest for current HMAC-state (preserves state).
 *	@param context	Pointer to an HMAC-state context.
 *	@param digest	Pointer to a buffer to write digest to.
 */
void cryptx_hmac_digest(struct cryptx_hmac_ctx* context, void* digest);

/**
 * @brief Derives a key from a password, salt, and round count.
 * @param password 	Pointer to a string containing the password.
 * @param passlen	Byte length of the password.
 * @param salt	 A psuedo-random string to use in each round of key derivation.
 * @param saltlen	Byte length of the salt.
 * @param rounds 	The number of times to iterate the HMAC function per block of @b keylen.
 * @param key		Pointer to buffer to write key to.
 * @param keylen	Length of @b key to generate.
 * @param hash_alg 	The numeric ID of the hashing algorithm to use. See @b cryptx_hash_algorithms.
 */
void cryptx_hmac_pbkdf2(const char* password,
						size_t passlen,
						const void* salt,
						size_t saltlen,
						uint8_t* key,
						size_t keylen,
						size_t rounds,
						uint8_t hash_alg);

/**
 * @brief Convert a bytearray to its hexstring representation.
 * @param buf	Pointer to bytearray to convert.
 * @param len		Byte length of @b digest.
 * @param hexstr	Buffer to write the output hex string to.
 */
bool cryptx_bytes_tostring(const void *buf, size_t len, char *hexstr);



bool cryptx_bytes_fromstring(void *buf, const char *hexstr);

/**
 * @brief Copies @b len bytes from @b src to @b dest while reversing the byte order.
 * @param dest  Pointer to a buffer to write bytes.
 * @param src   Pointer to a buffer to read bytes from.
 * @param len   Number of bytes to read.
 */
bool cryptx_bytes_rcopy(void *dest, const void *src, size_t len);

/**
 * @brief Reverses the byte order of a buffer in-place.
 * @param buf   Pointer to buffer to reverse.
 * @param len   Length of the buffer.
 */
bool cryptx_bytes_reverse(void *buf, size_t len);

/**
 * @brief Compare two bytearrays using a @b constant-time algorithm.
 * @param buf1	Pointer to first buffer to compare.
 * @param buf2	Pointer to second buffer to compare.
 * @param len		Number of bytes to compare.
 * @return @b true if the buffers are equal, @b false if not equal.
 */
bool cryptx_bytes_compare(const void *buf1, const void *buf2, size_t len);


/**
 * @brief Returns a securely psuedo-random 32-bit integer
 * @returns A securely psuedo-random 32-bit integer.
 */
uint32_t cryptx_csrand_get(void);

/**
 * @brief Fills a buffer with securely pseduo-random bytes
 * @param buffer	Pointer to a buffer to fill with random bytes.
 * @param size		Size of the buffer to fill.
 * @returns @b true on success, @b false on failure.
 * @returns @b buffer filled to size.
 */
bool cryptx_csrand_fill(void* buffer, size_t size);

/// ### ADVANCED ENCRYPTION STANARD ###
/// @struct Cipher state context for AES
struct cryptx_aes_ctx {
	uint24_t keysize;                       /**< the size of the key, in bits */
	uint32_t round_keys[60];                /**< round keys */
	uint8_t iv[16];                         /**< IV state for next block */
	uint8_t ciphermode;                     /**< selected operational mode of the cipher */
	uint8_t op_assoc;                       /**< state-flag indicating if context is for encryption or decryption*/
	cryptx_aes_private_h metadata;			/**< opague, internal context metadata */
};

enum cryptx_aes_cipher_modes {
	CRYPTX_AES_CBC,       /**< selects Cyclic Block Chain (CBC) mode */
	CRYPTX_AES_CTR,       /**< selects Counter (CTR) mode */
	CRYPTX_AES_GCM		/**< selects Galois Counter (GCM) mode */
};

enum cryptx_aes_padding_schemes {
	PAD_PKCS7,                  /**< PKCS#7 padding | DEFAULT */
	PAD_DEFAULT = PAD_PKCS7,	/**< selects the scheme marked DEFAULT.
								 Using this is recommended in case a change to the standards
								 would set a stronger padding scheme as default */
	PAD_ISO2					/**< ISO-9797 M2 padding */
};

#define CRYPTX_KEYLEN_AES128  16		/** Defines the byte length of an AES-128 key. */
#define CRYPTX_KEYLEN_AES192	24		/** Defines the byte length of an AES-192 key. */
#define CRYPTX_KEYLEN_AES256	32		/** Defines the byte length of an AES-256 key. */

#define CRYPTX_BLOCKSIZE_AES	16		/** Defines the AES block size, in bytes. Also the IV size and Auth Tag size. */

/** Defines defaults for various cipher modes */
enum cryptx_aes_default_flags {
  CRYPTX_AES_CBC_DEFAULTS = (PAD_DEFAULT | 0),
  CRYPTX_AES_CTR_DEFAULTS = (((0x0f & (8))<<6) | ((0x0f & (8))<<2) | 0),
  CRYPTX_AES_GCM_DEFAULTS = (0)
};

/** Defines a macro to set flags for AES CBC mode. */
#define cryptx_aes_cbc_flagset(padding_mode) \
  (padding_mode) | 0

/** Defines a macro to set flags for AES CTR mode. */
#define cryptx_aes_ctr_flagset(nonce_len, counter_len) \
  ((0x0f & (counter_len))<<6) | ((0x0f & (nonce_len))<<2) | 0

/** GCM has no flags, pass 0 .*/
#define cryptx_aes_gcm_flagset  0

/** Defines a macro to return the byte length of an AES ciphertext given a plaintext length.*/
#define cryptx_aes_get_ciphertext_len(len) \
((((len)%CRYPTX_BLOCKSIZE_AES)==0) ? (len) + CRYPTX_BLOCKSIZE_AES : (((len)>>4) + 1)<<4)

/// Defines response codes returned by the AES API.
typedef enum {
	AES_OK,                             /**< AES operation completed successfully */
	AES_INVALID_ARG,                    /**< AES operation failed, bad argument */
	AES_INVALID_MSG,                    /**< AES operation failed, message invalid */
	AES_INVALID_CIPHERMODE,             /**< AES operation failed, cipher mode undefined */
	AES_INVALID_PADDINGMODE,            /**< AES operation failed, padding mode undefined */
	AES_INVALID_CIPHERTEXT,             /**< AES operation failed, ciphertext error */
	AES_INVALID_OPERATION               /**< AES operation failed, used encrypt context for decrypt or vice versa */
} aes_error_t;

/**
 * @brief Initializes a stateful AES cipher context to be used for encryption or decryption.
 * @param context	Pointer to an AES cipher context to initialize.
 * @param key	Pointer to an 128, 192, or 256 bit key to load into the AES context.
 * @param keylen	The size, in bytes, of the @b key to load.
 * @param iv	Pointer to  Initialization vector, a buffer equal to the block size filled with random bytes.
 * @param ivlen	Length of the initalization vector. Capped at 16 bytes. Certain cipher modes have different recommendations.
 * @param cipher_mode Operational mode of the cipher to initialize.
 * @param flags	A series of flags to configure the AES context with. Use the provided @b defaults enumeration or the
 *              @b flagset macros above.
 * @returns An @b aes_error_t indicating the status of the AES operation.
 */
aes_error_t cryptx_aes_init(struct cryptx_aes_ctx* context,
							const void* key,
							size_t keylen,
							const void* iv,
							size_t ivlen,
              uint8_t cipher_mode,
							uint24_t flags);

/**
 * @brief Performs a stateful AES encryption of an arbitrary length of data.
 * @param context	Pointer to an AES cipher context.
 * @param plaintext	Pointer to data to encrypt.
 * @param len		Length of data at @b plaintext to encrypt.
 * @param ciphertext	Pointer to buffer to write encrypted data to.
 * @returns An @b aes_error_t indicating the status of the AES operation.
 */
aes_error_t cryptx_aes_encrypt(const struct cryptx_aes_ctx* context,
							   const void* plaintext,
							   size_t len,
							   void* ciphertext);

/**
 * @brief Performs a stateful AES decryption of an arbitrary length of data.
 * @param context		Pointer to AES cipher context.
 * @param ciphertext	Pointer to data to decrypt.
 * @param len		Length of data at @b ciphertext to decrypt.
 * @param plaintext	Pointer to buffer to write decryped data to.
 * @returns An @b aes_error_t indicating the status of the AES operation.
 */
aes_error_t cryptx_aes_decrypt(const struct cryptx_aes_ctx* context,
							   const void* ciphertext,
							   size_t len,
							   void* plaintext);

/**
 * @brief Updates the cipher context for given AAD (Additional Authenticated Data).
 * AAD is data that is only authenticated, not encrypted.
 * @param context	Pointer to an AES context.
 * @param aad		Pointer to additional authenticated data segment.
 * @param aad_len	Length of additional data segment.
 * @returns An @b aes_error_t indicating the status of the AES operation.
 */
aes_error_t cryptx_aes_update_aad(struct cryptx_aes_ctx* context,
								  const void* aad, size_t aad_len);

/**
 * @brief Returns the current authentication tag for data parsed so far.
 * @param context	Pointer to an AES context
 * @param digest	Pointer to a buffer to output digest to. Must be at least 16 bytes large.
 * @returns An @b aes_error_t indicating the status of the AES operation.
 */
aes_error_t cryptx_aes_digest(struct cryptx_aes_ctx* context, uint8_t *digest);

/**
 * @brief Parses the specified AAD and ciphertext and then compares the output auth tag
 * to an expected auth tag.
 * @param context	Pointer to an AES context.
 * @param aad		Pointer to associated data to authenticate.
 * @param aad_len	Length of associated data to authenticate.
 * @param ciphertext	Pointer to ciphertext to authenticate.
 * @param ciphertext_len	Length of ciphertext to authenticate.
 * @param tag		Pointer to expected auth tag to validate against.
 * @returns TRUE if authentication  tag matches expected, FALSE otherwise.
 */

bool cryptx_aes_verify(const struct cryptx_aes_ctx* context,
					   const void* aad, size_t aad_len,
					   const void* ciphertext, size_t ciphertext_len,
					   uint8_t *tag);

/// ### RIVEST-SHAMIR-ADLEMAN (RSA) ###

/// Defines response codes returned by calls to the RSA API.
typedef enum {
	RSA_OK,                         /**< RSA encryption completed successfully */
	RSA_INVALID_ARG,                /**< RSA encryption failed, bad argument */
	RSA_INVALID_MSG,                /**< RSA encryption failed, bad msg or msg too long */
	RSA_INVALID_MODULUS,            /**< RSA encryption failed, modulus invalid */
	RSA_ENCODING_ERROR              /**< RSA encryption failed, OAEP encoding error */
} rsa_error_t;

/** Defines the maximum byte length of an RSA public modulus supported by this library. */
#define CRYPTX_RSA_MODULUS_MAX		256

/**
 * @brief Encrypts a message using the given RSA public key.
 * @param msg	Pointer to a message to encrypt using RSA.
 * @param msglen	The byte length of the @b msg.
 * @param pubkey	Pointer to a public key to use for encryption.
 * @param keylen	The length of the public key (modulus) to encrypt with.
 * @param ciphertext 	Pointer a buffer to write the ciphertext to.
 * @param oaep_hash_alg	The numeric ID of the hashing algorithm to use within OAEP encoding.
 *      See @b cryptx_hash_algorithms.
 * @returns  An @b rsa_error_t indicating the status of the RSA operation.
 */
rsa_error_t cryptx_rsa_encrypt(const void* msg,
							   size_t msglen,
							   const void* pubkey,
							   size_t keylen,
							   void* ciphertext,
							   uint8_t oaep_hash_alg);


/// ### ELLIPTIC CURVE DIFFIE-HELLMAN ###
/// Using curve SECT233k1

/** Defines the byte length of a private key used by this module. */
#define CRYPTX_KEYLEN_EC_PRIVKEY  30

/** Defines the byte length of a public key used by this module.  */
#define CRYPTX_KEYLEN_EC_PUBKEY		(CRYPTX_KEYLEN_EC_PRIVKEY<<1)

/** Defines the byte length of a secret generated by this module.  */
#define CRYPTX_KEYLEN_EC_SECRET		CRYPTX_KEYLEN_EC_PUBKEY

/// Defines possible response codes from calls to the EC API.
typedef enum _ec_error {
	EC_OK,
	EC_INVALID_ARG,
	EC_PRIVKEY_INVALID,
	EC_RPUBKEY_INVALID
} ec_error_t;

/**
 * @brief Generates a pair of public/private keys over SECT233k1.
 * These keys are valid for ECDH and ECDSA.
 * @param privkey	Pointer to EC private key buffer.
 * @param pubkey	Pointer to EC public key buffer.
 * @returns A random 29-byte EC private key and associated public key.
 * @returns A response code indicating the return status of this function.
 */
ec_error_t cryptx_ec_keygen(uint8_t *privkey, uint8_t *pubkey);

/**
 * @brief Computes a secret given a private key and remote public key using the 
 * elliptic curve variant of the @b diffie-hellman key exchange algorithm (ECDH).
 * @param privkey	Pointer to local private key.
 * @param rpubkey	Pointer to remote public key.
 * @param secret	Pointer to buffer to write shared secret to.
 * @returns An @b ECDH secret for use with a symmetric encryption algorithm.
 * @returns A response code indicating the return status of this function.
 */
ec_error_t cryptx_ec_secret(const uint8_t *privkey, const uint8_t *rpubkey, uint8_t *secret);

/// ### ABSTRACT SYNTAX NOTATION ONE (ASN.1) ###

enum cryptx_asn1_tags {
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

enum cryptx_asn1_classes {
	ASN1_UNIVERSAL,			/**< tags defined in the ASN.1 standard. Most use cases on calc will be this. */
	ASN1_APPLICATION,		/**< tags unique to a particular application. */
	ASN1_CONTEXTSPEC,		/**< tags that need to be identified within a particular, well-definded context. */
	ASN1_PRIVATE			/**< reserved for use by a specific entity for their applications. */
};

enum cryptx_asn1_forms {
	ASN1_PRIMITIVE,			/**< this element should contain no nested elements. */
	ASN1_CONSTRUCTED,		/**< this element contains nested elements. */
};

/// Returns the unmasked tag. See @b cryptx_asn1_tags above.
#define cryptx_asn1_gettag(tag)		((tag) & 0b111111)
/// Returns the 2-bit tag class flag. See @b cryptx_asn1_classes above.
#define cryptx_asn1_getclass(tag)		(((tag)>>6) & 0b11)
/// Returns the 1-bit tag form (1 = constructed, 0 = primitive). See @b cryptx_asn1_forms above.
#define cryptx_asn1_getform(tag)		(((tag)>>5) & 1)

/// Defines error codes returned from calls to the ASN.1 API.
typedef enum {
	ASN1_OK,				/**< No errors occured. */
	ASN1_END_OF_FILE,		/**< End of ASN.1 data stream reached. Technically not an error. */
	ASN1_INVALID_ARG,		/**< One or more arguments invalid. */
	ASN1_LEN_OVERFLOW,		/**< Length of an element overflowed arch size\_t allowance. Remainder of data stream unparsable. */
} asn1_error_t;

/**
 * @brief Decodes the ASN.1 data at the given address. Seeks to an element from the front of the data.
 * @param data_start	Pointer to a block of ASN.1-encoded data.
 * @param data_len		Length of ASN.1-encoded block.
 * @param index               Number of ASN.1 elements to skip before returning one.
 * @param element_tag	Full element tag octet, or NULL if not needed.
 * @param element_len	Length of the returned element or NULL if not needed.
 * @param element_data	Pointer to the data of the returned element or NULL if not needed.
 * @returns				An @b asn1_error_t indicating the status of the operation.
 *                If @b index is past the end of the data, @b ASN1_END_OF_FILE is returned.
 */
asn1_error_t cryptx_asn1_decode(
					void *data_start,
					size_t data_len,
					uint8_t index,
					uint8_t *element_tag,
					size_t *element_len,
					uint8_t **element_data);


/** Defines a macro to return the expected base64-encoded data length, given octet-encoded @b len. This should be len \* 8 / 6. */
#define	cryptx_base64_get_encoded_len(len)		((len) * 4 / 3)

/** Defines a macro to return the expected octet-encoded data length, given base64-encoded @b len. This should be len \* 6 / 8. */
#define	cryptx_base64_get_decoded_len(len)		((len) * 3 / 4)

/**
 * @brief Converts an octet-encoded byte stream into a sextet-encoded byte stream.
 * @param dest Pointer to output sextet-encoded data stream.
 * @param src Pointer to input octet-encoded data stream.
 * @param len Length of octet-encoded data stream.
 * @returns Length of output sextet.
 */
size_t cryptx_base64_encode(void *dest, const void *src, size_t len);

/**
 * @brief Converts a sextet-encoded byte stream into a octet-encoded byte stream.
 * @param dest Pointer to output octet-encoded data stream.
 * @param src Pointer to input sextet-encoded data stream.
 * @param len Length of sextet-encoded data stream.
 * @returns Length of output octet.
 */
size_t cryptx_base64_decode(void *dest, const void *src, size_t len);

/// Defines a structure for holding imported RSA or ECC public key data.
struct cryptx_pkcs8_pubkeyinfo {
  struct  { uint8_t bytes[16]; size_t len; } objectid;
  union {
    struct {
      struct { uint8_t bytes[257]; size_t len; } modulus;
      uint24_t exponent;
    } rsa;
    struct {
      struct { uint8_t bytes[16]; size_t len; } curveid;
      bool compressed;
      uint8_t bytes[146]; size_t len;
    } ec;
  } publickey;
};

/// Defines a structure for holding imported RSA or ECC private key data.
struct cryptx_pkcs8_privkeyinfo {
  uint8_t version;
  struct  { uint8_t bytes[16]; size_t len; } objectid;
  union {
    struct {
      uint8_t version;
      struct { uint8_t bytes[257]; size_t len; } modulus;
      uint24_t public_exponent;
      struct { uint8_t bytes[257]; size_t len; } exponent;
      struct {
        struct { uint8_t bytes[129]; size_t len; } p;
        struct { uint8_t bytes[129]; size_t len; } q;
        struct { uint8_t bytes[129]; size_t len; } exp1;
        struct { uint8_t bytes[129]; size_t len; } exp2;
        struct { uint8_t bytes[129]; size_t len; } coeff;
      } parts;
    } rsa;
    struct {
      uint8_t version;
      struct { uint8_t bytes[16]; size_t len; } curveid;
      struct { uint8_t bytes[73]; size_t len; } private;
      struct { bool compressed; uint8_t bytes[146]; size_t len; } public;
    } ec;
  } privatekey;
};

/// Defines response codes returned by the PKCS8 API.
typedef enum {
  PKCS_OK,
  PKCS_INVALID_ARG,
  PKCS_UNSUPPORTED,
  PKCS_INVALID_DATA,
} pkcs_error_t;

/**
 * @brief Attempts to import a PKCS#8-encoded public key for RSA or ECC.
 * @param data Pointer to PKCS#8-encoded key data.
 * @param len   Length of key data to import.
 * @param keyinfo     Pointer to a @b cryptx_pkcs8_pubkeyinfo context to deserialize keydata into.
 * @returns @b keyinfo populated with appropriate data from the keyfile.
 * @returns A @b pkcs_error_t indicating the return status of the operation.
 */
pkcs_error_t cryptx_pkcs8_import_publickey(const void *data, size_t len,
                                           struct cryptx_pkcs8_pubkeyinfo *keyinfo);

/**
 * @brief Attempts to import a PKCS#8-encoded private key for RSA or ECC.
 * @param data Pointer to PKCS#8-encoded key data.
 * @param len   Length of key data to import.
 * @param keyinfo     Pointer to a @b cryptx_pkcs8_privkeyinfo context to deserialize keydata into.
 * @returns @b keyinfo populated with appropriate data from the keyfile.
 * @returns A @b pkcs_error_t indicating the return status of the operation.
 */
pkcs_error_t cryptx_pkcs8_import_privatekey(const void *data, size_t len,
                                           struct cryptx_pkcs8_privkeyinfo *keyinfo);



#ifdef CRYPTX_ENABLE_HAZMAT

/**
 @brief AES-ECB mode single block encryption
 @param block_in	Pointer to block of data to encrypt.
 @param block_out	Pointer to buffer to write block of encrypted data.
 @param ks	Pointer to AES key schedule.
 @note ECB mode is insecure. Use this function as a constructor for other cipher modes, not standalone.
 */
void cryptx_hazmat_aes_ecb_encrypt(const void *block_in,
									 void *block_out,
									 struct cryptx_aes_ctx* ks);

/**
 @brief AES-ECB mode single block decryption
 @param block_in	Pointer to block of data to decrypt.
 @param block_out	Pointer to buffer to write block of decrypted data.
 @param ks	Pointer to AES key schedule.
 @note ECB mode is insecure. Use this function as a constructor for other cipher modes, not standalone.
 */
void cryptx_hazmat_aes_ecb_decrypt(const void *block_in,
									 void *block_out,
									 struct cryptx_aes_ctx* ks);

/**
 @brief Optimal Asymmetric Encryption Padding v2.2 Encoder
 @param plaintext	Pointer to block of data to encode.
 @param len			Length of plaintext to encode.
 @param encoded		Pointer to buffer to write encoded output.
 @param modulus_len	Length of modulus to encode for (ex: length of RSA public modulus).
 @param auth		An optional string to include in the encoding (NULL to omit).
 @param hash_alg	Algorithm ID of the hash to use.
 @returns True on successful encoding, False on error.
 @note An error returned from the encoder usually is related to the size of plaintext. Maximum plaintext length
 for encoding is the length of the modulus minus twice the length of the selected hash digest minus two more
 padding bytes.
 */
bool cryptx_hazmat_rsa_oaep_encode(const void *plaintext,
									 size_t len,
									 void *encoded,
									 size_t modulus_len,
									 const uint8_t *auth,
									 uint8_t hash_alg);

/**
 @brief Optimal Asymmetric Encryption Padding v2.2 Decoder
 @param encoded		Pointer to block of data to decode.
 @param len			Length of plaintext to encode.
 @param plaintext	Pointer to buffer to write decoded output.
 @param auth		String included in the encoding (NULL to omit).
 @param hash_alg	Algorithm ID of the hash to use.
 @returns True on successful decoding, False on error.
 @note An error returned from the decoder usually means the input did not appear to be valid OAEP-encoded data.
 OAEP 2.2-encoded data starts with the byte *0x00*.
 */
bool cryptx_hazmat_rsa_oaep_decode(const void *encoded,
									 size_t len,
									 void *plaintext,
									 const uint8_t *auth,
									 uint8_t hash_alg);

/**
 @brief Modular Exponentation
 @param size	Length of the modulus, in bytes. *0* is actually 256.
 @param base	Pointer to the base.
 @param exp		Exponent.
 @param mod		Pointer to modulus.
 @note This is timing-safe if run from normal speed memory.
 */
void cryptx_hazmat_powmod(uint8_t size, uint8_t *restrict base, uint24_t exp, const uint8_t *restrict mod);

/// Defines the length of a galois field for a curve of degree 233.
#define CRYPTX_GF2_INTLEN 30

/// Defines a point for use with elliptic curve arithmetic.
struct cryptx_ecc_point {
	uint8_t x[CRYPTX_GF2_INTLEN];
	uint8_t y[CRYPTX_GF2_INTLEN];
}

/**
 @brief Elliptic Curve Point Addition over SECT233k1
 @param p	Pointer to first point to add.
 @param q	Pointer to second point to add.
 @note Outputs in @b p.
 */
void cryptx_hazmat_ecc_point_add(cryptx_ecc_point* p, cryptx_ecc_point* q);

/**
 @brief Elliptic Curve Point Doubling over SECT233k1
 @param p	Pointer to point to double.
 @note Outputs in @b p.
 */
void cryptx_hazmat_ecc_point_double(cryptx_ecc_point* p);

/**
 @brief Elliptic Curve Scalar Multiplication over SECT233k1
 @param p	Pointer to point to multiply.
 @param scalar	Pointer to scalar.
 @param scalar_bit_width	Length, in bits, of the scalar.
 @note Outputs in @b p.
 */
void cryptx_hazmat_ecc_point_mul_scalar(cryptx_ecc_point* p,
										  const uint8_t* scalar,
										  size_t scalar_bit_width);

#endif

#endif
