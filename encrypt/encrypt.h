/**
 * @file encrypt.h
 * @brief	Provides standard encryption for the TI-84+ CE.
 * @author Anthony @e ACagliano Cagliano
 * @author Adam @e beck Beckingham
 * @author commandblockguy
 *
 * Provides symmetric and asymmetric (pubkey) encryption as well as a HWRNG.
 * 1. Secure HWRNG
 * 2. AES-128, AES-192, AES-256
 * 3. RSA + OAEP v2.2
 * 4. ECDH, using NIST K-233, cofactor variant.
 *
 * Access to some internal functions through defines that should be placed in your source before including this header:
 *
 */

#ifndef encrypt_h
#define encrypt_h
#include <hashlib.h>

//******************************************************************************************
/*	INTERNAL OBJECT DEFINITIONS
 
 This section defines INTERNAL OBJECTS used by the library in functions not
 exposed to the users. These are here so that metadata portions of the context
 structures defined later are correct.
 */

// Internal structures for AES cipher modes
struct cryptx_aes_cbc_state { uint8_t padding_mode; };
struct cryptx_aes_ctr_state {
	uint8_t counter_pos_start; uint8_t counter_len;
	uint8_t last_block_stop; uint8_t last_block[16]; };
struct cryptx_aes_gcm_state {
	uint8_t ghash_key[16];
	uint8_t auth_tag[16];
	size_t assoc_len; };

typedef union {
	struct cryptx_aes_gcm_state gcm;					/**< metadata for GCM mode */
	struct cryptx_aes_cbc_state ctr;                    /**< metadata for counter mode */
	struct cryptx_aes_ctr_state cbc;                    /**< metadata for cbc mode */
} cryptx_aes_private_h;


//******************************************************************************************
/*	Cryptographically-Secure Random Number Generator (CSRNG)
 
	This library provides an entropy-based hardware (HW)RNG. The entropy is sourced
	from bus noise derived from the behavior of bit lines in floating memory.
	For further details, see the documentation.
 
	Many random number generators, including the rand() implementation provided by
	the toolchain are only statistically random, but not unpredictable. That suffices
	for many applications but not for cryptography. Otherwise-secure cryptography can be defeated
	if the primative that generates keys and salts is predictable. To that end, the developers
	of this library put significant effort into constructing a generator that satifies the
	constraints for cryptographic security to the best extent possible on the hardware. */

/*******************************************
 * @enum cryptx\_srng\_sampling\_mode
 * Defines sampling modes for @b cryptx\_csrand\_init
 */
typedef enum cryptx_csrng_sampling_modes {
	SAMPLING_THOROUGH	= 0,
	SAMPLING_FAST		= 1
} cryptx_csrng_sampling_mode;

/*******************************************************************************
 * @brief Initializes the (HW)RNG.
 * @param[in] sampling_mode	Sampling mode to use for finding an entropic bit. See @b cryptx_csrng_sampling_mode.
 * @returns @b true on success, @b false on failure.
 * @note Sampling mode controls the speed (and accuracy) of the source-selection algorithm.
 * Setting SAMPLING\_THOROUGH retrieves 1024 samples per bit polled and takes ~4 seconds to run.
 * Setting SAMPLING\_FAST retrieves 512 samples per bit polled and takes ~2 seconds to run.
 * @note Using the faster sampling mode may result in a less-entropic source byte being selected due to less
 * samples being collected. It is recommended to use THOROUGH.
 */
bool cryptx_csrand_init(cryptx_csrng_sampling_mode mode);

/***********************************************
 * @brief Returns a securely psuedo-random 32-bit integer
 * @returns A securely psuedo-random 32-bit integer.
 */
uint32_t cryptx_csrand_get(void);

/**************************************************
 * @brief Fills a buffer with securely pseduo-random bytes
 * @param[in] buffer	Pointer to a buffer to fill with random bytes.
 * @param[in] size		Size of the buffer to fill.
 * @returns @b true on success, @b false on failure.
 * @returns @b buffer filled to size.
 */
bool cryptx_csrand_fill(void* buffer, size_t size);


//******************************************************************************************
/*	Advanced Encryption Standard (AES)
 
	AES is form of symmetric encryption. It is a fast algorithm that can encrypt
	arbitrary lengths of data in blocks of 128 bits (16 bytes).

	The AES algorithm has 3 variants, each of which takes a key of different length.
	AES-128 takes a 128 bit (16 byte) key and performs 10 rounds of encryption.
	AES-192 takes a 192 bit (24 byte) key and performs 12 rounds of encryption.
	AES-256 takes a 256 bit (32 byte) key and performs 14 rounds of encryption.
 
	AES is one of the most secure encryption systems in use today.
	AES-256 is the most secure variant of the algorithm. */


/***********************************************
 * @struct cryptx\_aes\_ctx
 * Defines a stateful context for use with one side of an AES session.
 */
struct cryptx_aes_ctx {
	uint24_t keysize;                       /**< the size of the key, in bits */
	uint32_t round_keys[60];                /**< round keys */
	uint8_t iv[16];                         /**< IV state for next block */
	uint8_t ciphermode;                     /**< selected operational mode of the cipher */
	uint8_t op_assoc;                       /**< state-flag indicating if context is for encryption or decryption*/
	cryptx_aes_private_h metadata;			/**< opague, internal context metadata */
};

/*************************
 * @enum aes\_cipher\_modes
 * Defines supported AES cipher modes.
 */
enum cryptx_aes_cipher_modes {
	AES_MODE_CBC,       /**< selects CBC mode */
	AES_MODE_CTR,       /**< selects CTR mode */
	AES_MODE_GCM
};

/****************************
 * @enum aes\_padding\_schemes
 * Defines supported AES padding schemes.
 */
enum cryptx_aes_padding_schemes {
	PAD_PKCS7,                  /**< PKCS#7 padding | DEFAULT */
	PAD_DEFAULT = PAD_PKCS7,	/**< selects the scheme marked DEFAULT.
								 Using this is recommended in case a change to the standards
								 would set a stronger padding scheme as default */
	PAD_ISO2					/**< ISO-9797 M2 padding */
};

/** Defines the byte length of an AES-128 key. */
#define CRYPTX_AES128_KEYLEN	16

/** Defines the byte length of an AES-192 key. */
#define CRYPTX_AES192_KEYLEN	24

/** Defines the byte length of an AES-256 key. */
#define CRYPTX_AES256_KEYLEN	32

/** Defines the block size of the AES block, in bytes. */
#define CRYPTX_AES_BLOCK_SIZE		16

/** Defines the length of the AES initialization vector, in bytes. */
#define CRYPTX_AES_IV_SIZE		CRYPTX_AES_BLOCK_SIZE

/** Defines a macro to return the byte length of an AES ciphertext given a plaintext length.*/
#define CRYPTX_AES_CIPHERTEXT_LEN(len) \
	((((len)%CRYPTX_AES_BLOCK_SIZE)==0) ? (len) + CRYPTX_AES_BLOCK_SIZE : (((len)>>4) + 1)<<4)

/** Defines a macro to enable AES CBC cipher mode and pass relevant configuration options.*/
#define CRYPTX_AES_CBC_FLAGS(padding_mode) \
	((padding_mode)<<2) | AES_MODE_CBC

/** Defines a macro to enable AES CTR cipher mode and pass relevant configuration options.*/
#define CRYPTX_AES_CTR_FLAGS(nonce_len, counter_len)	\
	((0x0f & (counter_len))<<8) | ((0x0f & (nonce_len))<<4) | AES_MODE_CTR

#define CRYPTX_AES_GCM_FLAGS	AES_MODE_GCM

/*******************************************
 * @typedef aes\_error\_t
 * Defines response codes that can be returned from calls
 * to the AES API.
 */
typedef enum {
	AES_OK,                             /**< AES operation completed successfully */
	AES_INVALID_ARG,                    /**< AES operation failed, bad argument */
	AES_INVALID_MSG,                    /**< AES operation failed, message invalid */
	AES_INVALID_CIPHERMODE,             /**< AES operation failed, cipher mode undefined */
	AES_INVALID_PADDINGMODE,            /**< AES operation failed, padding mode undefined */
	AES_INVALID_CIPHERTEXT,             /**< AES operation failed, ciphertext error */
	AES_INVALID_OPERATION               /**< AES operation failed, used encrypt context for decrypt or vice versa */
} aes_error_t;

/********************************************************************
 * @brief Initializes a stateful AES cipher context to be used for encryption or decryption.
 * @param[in] context	Pointer to an AES cipher context to initialize.
 * @param[in] key	Pointer to an 128, 192, or 256 bit key to load into the AES context.
 * @param[in] keylen	The size, in bytes, of the @b key to load.
 * @param[in] iv	Pointer to  Initialization vector, a buffer equal to the block size filled with random bytes.
 * @param[in] flags	A series of flags to configure the AES context with.
 * 				Use the provided @b CRYPTX_AES_CTR_FLAGS or @b CRYPTX_AES_CBC_FLAGS to pass flags.
 * @returns An @b aes_error_t indicating the status of the AES operation.
 * @note Contexts are not bidirectional due to being stateful. If you need to process both encryption and decryption,
 * initialize seperate contexts for encryption and decryption. Both contexts will use the same key, but different initialization vectors.
 * @warning It is recommended to cycle your key after encrypting 2^64 blocks of data with the same key.
 * @warning Do not manually edit the @b ctx.mode field of the context structure.
 * This will break the cipher configuration. If you want to change cipher modes, do so by calling @b aes_init again.
 * @warning AES-CBC and CTR modes ensure confidentiality but do not provide message integrity verification.
 * If you need a truly secure construction, append a keyed hash (HMAC) to the encrypted message..
 */
aes_error_t cryptx_aes_init(
				struct cryptx_aes_ctx* context,
				const void* key,
				size_t keylen,
				const void* iv,
				size_t iv_len,
				uint24_t flags);

/****************************************************************
 * @brief Performs a stateful AES encryption of an arbitrary length of data.
 * @param[in] context	Pointer to an AES cipher context.
 * @param[in] plaintext	Pointer to data to encrypt.
 * @param[in] len		Length of data at @b plaintext to encrypt.
 * @param[out] ciphertext	Pointer to buffer to write encrypted data to.
 * @returns An @b aes_error_t indicating the status of the AES operation.
 * @note @b ciphertext should large enough to hold the encrypted message.
 *          For CBC mode, this is the smallest multiple of the blocksize that will hold the plaintext.
 *          See the @b CRYPTX_AES_CIPHERTEXT_LEN macro.
 *          For CTR mode, this is the same size as the plaintext.
 * @note @b plaintext and @b ciphertext are aliasable.
 * @note Encrypt is streamable, such that encrypt(msg1) + encrypt(msg2) is functionally identical to encrypt(msg1+msg2)
 * with the exception of intervening padding in CBC mode.
 * @note Once a  context is used for encryption, it cannot be used for decryption.
 */
aes_error_t cryptx_aes_encrypt(
					const struct cryptx_aes_ctx* context,
					const void* plaintext,
					size_t len,
					void* ciphertext);

/*************************************************************
 * @brief Performs a stateful AES encryption of an arbitrary length of data.
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
aes_error_t cryptx_aes_decrypt(
					const struct cryptx_aes_ctx* context,
					const void* ciphertext,
					size_t len,
					void* plaintext);


aes_error_t cryptx_aes_update_assoc(
					const struct cryptx_aes_ctx* context,
					void* aad, size_t aad_len);


aes_error_t cryptx_aes_render_digest(const struct cryptx_aes_ctx* context, uint8_t *digest);


//******************************************************************************************
/*	RSA Public Key Encryption
 
	RSA is a form of public key encryption. In this construction, both parties need
	a public key and a private key. Typically the public key is used to encrypt messages
	bound for a specific host and the private key is used to decrypt those messages.
	In a public key system anyone can encrypt messages for a specific user since the public
	key is sent in the clear (hence the term 'public'). However, only the specific host can
	decrypt those messages as the private key is not shared.
 
	The cryptographic strength of RSA comes from the difficulty of prime factorization
	of huge numbers. However, in recent times, hardware has gotten good at solving this
	problem. 1024 bit RSA has recently been broken and a minimum of 2048 bits is recommended
	at present.
 
	Asymmetric encryption is VERY slow. Using even RSA-1024 on the TI-84+ CE will
	take several seconds. For this reason, you usually do not use RSA for sustained encrypted
	communication. Use RSA to share a symmetric key, and then use AES for future messages.
 
 */

/******************************************
 * @typedef rsa\_error\_t
 * Defines response codes that can be returned from calls
 * to the RSA API.
 */
typedef enum {
	RSA_OK,                         /**< RSA encryption completed successfully */
	RSA_INVALID_ARG,                /**< RSA encryption failed, bad argument */
	RSA_INVALID_MSG,                /**< RSA encryption failed, bad msg or msg too long */
	RSA_INVALID_MODULUS,            /**< RSA encryption failed, modulus invalid */
	RSA_ENCODING_ERROR              /**< RSA encryption failed, OAEP encoding error */
} rsa_error_t;

/** Defines the maximum byte length of an RSA public modulus supported by this library. */
#define CRYPTX_RSA_MODULUS_MAX		256

/*****************************************************
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
rsa_error_t cryptx_rsa_encrypt(
					const void* msg,
					size_t msglen,
					const void* pubkey,
					size_t keylen,
					void* ciphertext,
					uint8_t oaep_hash_alg);


//******************************************************************************************
/*	Elliptic Curve Diffie-Hellman (ECDH)
 
	Elliptic curve Diffie-Hellman is a form of elliptic curve cryptography.
	It is a variant of the standard Diffie-Hellman key negotiation protocol that
	uses elliptic curve point arithmetic over a finite field as an alternative to
	multiplication modulo some large prime number. Due to the ease in which large
	primes can be factored today, standard Diffie-Hellman requires large keys, often
	in excess of 2048 bits, just like with RSA.
 
	Elliptic curve Diffie-Hellman is a very different animal. Due to the mathematical complexity
	of the structure of a curve over a finite field, encryption based on them is significantly
	harder to crack. This also means that much smaller key sizes are required. For example, the
	SECT233k1 standard uses a curve of degree 233, which also defines the maximum bit length
	of the private key. Just 233 bits for ECDH. Versus >2048 for standard DH.
 
	Elliptic curve Diffie-Hellman works by allowing two users to generate a private key at random
	and initialize a base point (G) on the same standard-defined curve. That point is multiplied
	by the private key to produce a public key. Both parties then exchange public keys. The
	nature of the algebraic relationship between these keys is such that both parties can multiply
	the other party's public key with their own private key to produce the same secret.
 */

/** Defines the byte length of an ECDH private key supported by this library. */
#define CRYPTX_ECDH_PRIVKEY_SIZE	30

/** Defines the byte length of an ECDH public key supported by this library.  */
#define CRYPTX_ECDH_PUBKEY_SIZE		(CRYPTX_ECDH_PRIVKEY_SIZE<<1)

struct cryptx_ecdh_ctx {
	uint8_t privkey[CRYPTX_ECDH_PRIVKEY_SIZE];
	uint8_t pubkey[CRYPTX_ECDH_PUBKEY_SIZE];
};

/**************************
 * @enum ecdh\_error\_t
 * Defines status codes for ECDH
 */
typedef enum _ecdh_error {
	ECDH_OK,
	ECDH_INVALID_ARG,
	ECDH_PRIVKEY_INVALID,
	ECDH_RPUBKEY_INVALID
} ecdh_error_t;

/************************************************************************
 * @brief Initializes an ECDH context.
 * @param[in] context	Pointer to an ECDH context containing reserved public and private key buffers.
 * @note Output public key is a point on the curve expressed as two 30-byte coordinates
 * encoded in little endian byte order and padded with zeros (if needed). You may have to
 * deserialize the key and then serialize it into a different format to use it with
 * some encryption libraries.
 * @note This function automatically generates a random private key using @b csrand_fill prior to
 * the generation of the public key. For ease of use, this cannot be disabled. To access the private
 * key you will need to reference @b context.privkey. To access the public key you will need to
 * reference @b context.pubkey.
 */
ecdh_error_t cryptx_ecdh_init(struct cryptx_ecdh_ctx* context);

/***************************************************************
 * @brief Computes a secret given an ECDH context and some remote public key.
 * Given local private key and remote public key, generate a secret.
 * @param[in] ctx	Pointer to context containing local private key.
 * @param[in] rpubkey	Pointer to remote public key.
 * @param[out] secret	Pointer to buffer to write shared secret to.
 * @note @b secret must be at least @b ECDH_PUBKEY_SIZE bytes.
 * @note Output secret is a point on the curve expressed as two 30-byte coordinates
 * encoded in little endian byte order and padded with zeros if needed. You may have to
 * deserialize the secret and then serialize it into a different format for compatibility with
 * other encryption libraries.
 * @note It is generally not recommended to use the computed secret as an encryption key as is.
 * It is preferred to pass the secret to a KDF or a cryptographic primitive such as a hash function and use
 * that output as your symmetric key.
 */
ecdh_error_t cryptx_ecdh_secret(const struct cryptx_ecdh_ctx *context, const uint8_t *rpubkey, uint8_t *secret);


//******************************************************************************************
/*	ADVANCED MODE

	### PROCEED WITH CAUTION ###
	Enable advanced mode by including: #define CRYPTX_ENABLE_INTERNAL in your
	C source file BEFORE including this header.
	
	Advanced mode exposes some primatives that can be used by those who know what
	they are doing to construct protocols different than those provided by the main
	library API. They are not there to be used as is. Some of the underlying primatives
	are insecure on their own, such as AES ECB mode.
 
	Also bear in mind that there is no guarantee that these functions provide all of
	the side-channel defenses that the main library API provides, namely disabling interrupts
	while data transformation is underway and stack frame purging when it is complete.
 */

#ifdef CRYPTX_ENABLE_INTERNAL

/*****************************************************
 * @brief AES single-block ECB mode encryption function
 * @param block_in Block of data to encrypt.
 * @param block_out Buffer to write encrypted block of data.
 * @param ks AES key schedule context to use for encryption.
 * @note @b block_in and @b block_out are aliasable.
 * @warning ECB mode encryption is insecure (see many-time pad vulnerability).
 *     Use ECB-mode block encryptors as a constructor for custom cipher modes only.
 */
void cryptx_internal_aes_ecb_encrypt(const void *block_in, void *block_out, struct cryptx_aes_ctx* ks);

/*****************************************************
 * @brief AES single-block ECB mode decryption function
 * @param block_in Block of data to encrypt.
 * @param block_out Buffer to write encrypted block of data.
 * @param ks AES key schedule context to use for encryption.
 * @note @b block_in and @b block_out are aliasable.
 * @warning ECB mode encryption is insecure (see many-time pad vulnerability).
 *     Use ECB-mode block encryptors as a constructor for custom cipher modes only.
 */
void cryptx_internal_aes_ecb_decrypt(const void *block_in, void *block_out, struct cryptx_aes_ctx* ks);

/*************************************************************
 * @brief Optimal Asymmetric Encryption Padding (OAEP) encoder for RSA
 * @param plaintext Pointer to the plaintext message to encode.
 * @param len Lengfh of the message to encode.
 * @param encoded Pointer to buffer to write encoded message to.
 * @param modulus_len Length of the RSA modulus to encode for.
 * @param auth An authentication string to include in the encoding. Can be NULL to omit.
 * @param hash_alg The numeric ID of the hashing algorithm to use. See @b hash_algorithms.
 * @return Boolean | True if encoding succeeded, False if encoding failed.
 * @note @b plaintext and @b encoded are aliasable.
 */
bool cryptx_internal_rsa_oaep_encode(
			const void *plaintext,
			size_t len,
			void *encoded,
			size_t modulus_len,
			const uint8_t *auth,
			uint8_t hash_alg);

/************************************************
 * @brief OAEP decoder for RSA
 * @param encoded Pointer to the plaintext message to decode.
 * @param len Lengfh of the message to decode.
 * @param plaintext Pointer to buffer to write decoded message to.
 * @param auth An authentication string to include in the encoding. Can be NULL to omit.
 * @param hash_alg The numeric ID of the hashing algorithm to use. See @b hash_algorithms.
 * @return Boolean | True if encoding succeeded, False if encoding failed.
 * @note @b plaintext and @b encoded are aliasable.
 */
bool cryptx_internal_rsa_oaep_decode(
			const void *encoded,
			size_t len,
			void *plaintext,
			const uint8_t *auth,
			uint8_t hash_alg);

/***********************************************************
 * @brief Modular Exponentiation function for RSA (and other implementations)
 * @param size The length, in bytes, of the @b base and @b modulus.
 * @param base Pointer to buffer containing the base, in bytearray (big endian) format.
 * @param exp A 24-bit exponent.
 * @param mod Pointer to buffer containing the modulus, in bytearray (big endian) format.
 * @note For the @b size field, the bounds are [0, 255] with 0 actually meaning 256.
 * @note @b size must not be 1.
 * @note @b exp must be non-zero.
 * @note @b modulus must be odd.
 */
void cryptx_internal_powmod(
		uint8_t size,
		uint8_t *restrict base,
		uint24_t exp,
		const uint8_t *restrict mod);


/*****************************************
 * @define GF2\_BIGINT\_SIZE
 * Defines the max length of a GF2\_BIGINT.
 */
#define GF2_INTLEN		ECDH_PRIVKEY_SIZE

/*************************************************************
 * @brief Converts a bytearray to a Galois Field (2^m) big integer.
 * @param dest Pointer to a @b GF2_BIGINT type to load bytes into.
 * @param src Pointer to a bytearray to load.
 * @param len Length of the input bytearray.
 * @param big_endian Determines the endianness of the GF2\_BIGINT. If @b true, then
 * the integer will be encoded big endian. If false, it will be encoded little endian.
 */
bool cryptx_internal_gf2_frombytes(uint8_t* gf2_bigint, const void *restrict src, size_t len, bool big_endian);

/*************************************************************
 * @brief Converts a Galois Field (2^m) big integer to a bytearray.
 * @param dest Pointer to a buffer to write bytes to.
 * @param src Pointer to a GF2\_BIGINT to convert to bytes.
 * @param big_endian Indicates the endianness of the BIGINT. If @b true, then
 * this function is essentially a @b memcpy of 32 bytes from  @b src to @b dest.
 * If @b false, then the bytes will be copied backwards.
 */
bool cryptx_internal_gf2_tobytes(void *dest, const uint8_t restrict* gf2_bigint, bool big_endian);

/***********************************************************
 * @brief Performs a Galois field addition of two big integers.
 * @param res A big integer to write result to.
 * @param op1 The first big integer operand.
 * @param op2 The second big integer operand.
 * @note @b res and @b op1 are aliasable.
 * @note This is not a not a normal addition of two big integers. It is binary Galois
 * field addition (addition modulo 2), or simply just XOR.
 */
void cryptx_internal_gf2_add(uint8_t* res, uint8_t* op1, uint8_t* op2);

/***********************************************************
 * @brief Performs a Galois field multiplication of two big integers.
 * @param res A big integer to write result to.
 * @param op1 The first big integer operand.
 * @param op2 The second big integer operand.
 * @note @b res and @b op1 are aliasable.
 * @note @b op1 and @b op2 are aliasable.
 * @warning @b res and @b op2 ARE NOT ALIASABLE.
 * @note This is not a not a normal multiplication of two big integers. It is a
 * multiplication over the finite field defined by the polynomial: x^233 + x^74 + 1.
 */
void cryptx_internal_gf2_mul(uint8_t* res, uint8_t* op1, uint8_t* op2);

/***********************************************************
 * @brief Performs a Galois field squaring of a big integer.
 * @param res A big integer to write result to.
 * @param op The big integer operand.
 * @note @b res and @b op are aliasable.
 * @note This is not a not a normal squaring. It is a square
 * over the finite field defined by the polynomial: x^233 + x^74 + 1.
 */
void cryptx_internal_gf2_square(uint8_t* res, uint8_t* op);

/***********************************************************
 * @brief Performs a Galois field inversion of a big integer.
 * @param res A big integer to write result to.
 * @param op The big integer operand.
 * @note @b res and @b op are aliasable.
 * @note This is not a not a normal multiplicative inverse. It is an inversion
 * over the finite field defined by the polynomial: x^233 + x^74 + 1.
 */
void cryptx_internal_gf2_invert(uint8_t* res, uint8_t* op);


/*******************************************
 * @struct cryptx\_ecc\_point
 * Defines a point to be used for elliptic curve point arithmetic.
 */

struct cryptx_ecc_point {
	uint8_t x[GF2_INTLEN];
	uint8_t y[GF2_INTLEN];
}

/**********************************************
 * @brief Performs a point addition over the sect233k1 curve.
 * @param p Defines the first input point.
 * @param q Defines the second input point.
 * @returns The resulting point in @b p.
 */
void cryptx_internal_ecc_point_add(cryptx_ecc_point* p, cryptx_ecc_point* q);

/**********************************************
 * @brief Performs a point double over the sect233k1 curve.
 * @param p Defines the input point to double.
 * @returns The resulting point in @b p.
 */
void cryptx_internal_ecc_point_double(cryptx_ecc_point* p);

/**********************************************************
 * @brief Performs a scalar multiplication of a point over the sect233k1 curve.
 * @param p Defines the input point to multiply.
 * @param scalar Defines the scalar to multiply by.
 * @param scalar_bit_width The length of the scalar, in bits.
 * @returns The resulting point in @b p.
 */
void cryptx_internal_ecc_point_mul_scalar(cryptx_ecc_point* p, const uint8_t* scalar, size_t scalar_bit_width);

#endif

#endif
