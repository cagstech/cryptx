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

/*
 Cryptographically-Secure Random Number Generator (CSRNG)
 
 This library provides an entropy-based hardware (HW)RNG. The entropy is sourced
 from bus noise derived from the behavior of bit lines in floating memory.
 For further details, see the documentation.
 
 Many random number generators, including the rand() implementation provided by
 the toolchain are only statistically random, but not unpredictable. That suffices
 for many applications but not for cryptography. Otherwise secure cryptography can be defeated
 if the primative that generates keys and salts is predictable. To that end, the developers
 of this library put significant effort into constructing a generator that satifies the
 constraints for cryptographic security to the best level possible on the hardware.
 */

/************************************
 * @enum sampling\_mode
 * Defines sampling modes for @b csrand\_init
 */
enum cryptx_srng_sampling_mode {
	SAMPLING_THOROUGH,
	SAMPLING_FAST
};

/*******************************************************************************
 * @brief Initializes the secure psuedo-random generator
 * @param sampling_mode Sampling mode to use for finding an entropic bit. See @b sampling_mode.
 * @return [bool] True if init succeeded, False otherwise
 * @note Sampling mode controls the speed (and accuracy) of the source-selection algorithm.
 * Setting SAMPLING\_THOROUGH retrieves 1024 samples per bit polled and takes ~4 seconds to run.
 * Setting SAMPLING\_FAST retrieves 512 samples per bit polled and takes ~2 seconds to run.
 * @note Using the faster sampling mode may result in a less-entropic source byte being selected due to less
 * samples being collected. It is recommended to use THOROUGH.
 */
bool cryptx_csrand_init(bool sampling_mode);

/***********************************************
 * @brief Returns a securely psuedo-random 32-bit integer
 * @return [uint32_t] A 32-bit random number.
 */
uint32_t cryptx_csrand_get(void);

/**************************************************
 * @brief Fills a buffer with securely pseduo-random bytes
 * @param buffer Pointer to a buffer to fill with random bytes
 * @param size Size of the buffer to fill
 */
bool cryptx_csrand_fill(void* buffer, size_t size);

/*
 Advanced Encryption Standard (AES)
 
 AES is a form of symmetric encryption, and also is a form of block cipher.
 Symmetric encryption means that the same key works in both directions.
 A block cipher is an encryption algorithm that operates on data in segments (for AES, 16 bytes),
 moving through it one segment at a time.
 
 Symmetric encryption is usually fast, and is generally more secure for smaller key sizes.
 AES is one of the most secure encryption systems in use today.
 The most secure version of the algorithm is AES-256 (uses a 256-bit key).
 AES is one of the open-source encryption schemes believed secure enough to withstand even
 the advent of quantum computing.
 */

/*******************************
 * @struct aes_ctx
 * Stores AES cipher configuration data.
 */
struct _cryptx_aes_cbc { uint8_t padding_mode; };
struct _cryptxaes_ctr {
	uint8_t counter_pos_start; uint8_t counter_len;
	uint8_t last_block_stop; uint8_t last_block[16]; };

struct cryptx_aes_ctx {
	uint24_t keysize;                       /**< the size of the key, in bits */
	uint32_t round_keys[60];                /**< round keys */
	uint8_t iv[16];                         /**< IV state for next block */
	uint8_t ciphermode;                     /**< selected operational mode of the cipher */
	union {
		struct _cryptx_aes_cbc ctr;                      /**< metadata for counter mode */
		struct _cryptx_aes_ctr cbc;                      /**< metadata for cbc mode */
	} _internal;
	uint8_t op_assoc;                       /**< state-flag indicating if context is for encryption or decryption*/
};


/*************************
 * @enum aes_cipher_modes
 * Supported AES cipher modes
 */
enum cryptx_aes_cipher_modes {
	AES_MODE_CBC,       /**< selects CBC mode */
	AES_MODE_CTR        /**< selects CTR mode */
};

/****************************
 * @enum aes_padding_schemes
 * Supported AES padding schemes
 */
enum cryptx_aes_padding_schemes {
	PAD_PKCS7,                  /**< PKCS#7 padding | DEFAULT */
	PAD_DEFAULT = PAD_PKCS7,	/**< selects the scheme marked DEFAULT.
								 Using this is recommended in case a change to the standards
								 would set a stronger padding scheme as default */
	PAD_ISO2 = 4,               /**< ISO-9797 M2 padding */
};

/**********************************
 * @def AES_BLOCKSIZE
 * Defines the block size of the AES cipher.
 */
#define AES_BLOCKSIZE	16

/*****************************************
 * @def AES_IVSIZE
 * Defines the length of the AES initialization vector (IV)
 */
#define AES_IVSIZE		AES_BLOCKSIZE

/**********************************************************
 * @define AES\_CIPHERTEXT\_LEN(plaintext\_len)
 * Defines a macro to return the size of an AES ciphertext given a plaintext length..
 */
#define AES_CIPHERTEXT_LEN(plaintext_len) \
((((plaintext_len)%AES_BLOCKSIZE)==0) ? (len) + AES_BLOCKSIZE : (((len)>>4) + 1)<<4)

/*************************************************************
 * @define AES\_CBC\_FLAGS
 * Defines a macro for enabling CBC cipher mode and setting relevant configuration.
 */
#define AES_CBC_FLAGS(padding_mode) \
	(padding_mode) | AES_MODE_CBC

/*************************************************************
 * @define AES\_CTR\_FLAGS
 * Defines a macro for enabling CTR cipher mode and setting relevant configuration.
 */
#define AES_CTR_FLAGS(nonce_len, counter_len)	\
	((0x0f & (counter_len))<<8) | ((0x0f & (nonce_len))<<4) | AES_MODE_CTR

/*******************
 * @enum aes_error_t
 * AES error codes
 */
typedef enum {
	AES_OK,                             /**< AES operation completed successfully */
	AES_INVALID_ARG,                    /**< AES operation failed, bad argument */
	AES_INVALID_MSG,                    /**< AES operation failed, message invalid */
	AES_INVALID_CIPHERMODE,             /**< AES operation failed, cipher mode undefined */
	AES_INVALID_PADDINGMODE,            /**< AES operation failed, padding mode undefined */
	AES_INVALID_CIPHERTEXT,             /**< AES operation failed, ciphertext error */
	AES_INVALID_OPERATION               /**< AES operation failed, used encrypt context for decrypt or vice versa */
} aes_error;

/********************************************************************
 * @brief Initializes a stateful AES cipher context to be used for encryption or decryption.
 * @param ctx Pointer to an AES cipher context to initialize..
 * @param key Pointer to an 128, 192, or 256 bit key to load into the AES context.
 * @param keylen The size, in bytes, of the key to load.
 * @param iv Initialization vector, a buffer equal to the block size that is pseudo-random.
 * @param flags A series of flags to configure the AES context with. Use the provided @b AES_CTR_FLAGS or @b AES_CBC_FLAGS macro for this.
 * @note Do not edit a context manually. You may corrupt the cipher state.
 * @note Contexts are not bidirectional due to being stateful. If you need to process both encryption and decryption, initialize seperate contexts for encryption and decryption. Both contexts will use the same key, but different initialization vectors.
 * @warning It is recommended to cycle your key after encrypting 2^64 blocks of data with the same key.
 * @warning Do not manually edit the @b ctx.mode field of the context structure. This will break the cipher configuration. If you want to change cipher modes, do so by calling @b aes_init again.
 * @warning AES-CBC and CTR modes ensure confidentiality but do not guard against tampering. AES-OCB/GCM are a bit computationallty-intensive for this platform, but HASHLIB provides hash and hmac functions in their stead. HMAC is generally more secure for this purpose.
 * If you want a truly secure scheme, always append an HMAC to your message and use an application secret or unique key generated using a CSRNG to key the HMAC at both endpoints.
 * @return AES_OK if success, non-zero if failed. See aes_error_t.
 */
aes_error cryptx_aes_init(
				struct cryptx_aes_ctx* context,
				const void* key,
				size_t keylen,
				const void* iv,
				uint24_t flags);

/*****************************************************
 * @brief General-Purpose AES Encryption
 * @param ctx Pointer to an AES cipher context.
 * @param plaintext Pointer to data to encrypt.
 * @param len Length of data at @b plaintext to encrypt. This can be the output of hashlib_AESCiphertextSize().
 * @param ciphertext Pointer to buffer to write encrypted data to.
 * @note @b ciphertext should large enough to hold the encrypted message.
 *          For CBC mode, this is the smallest multiple of the blocksize that will hold the plaintext,
 *              plus 1 block if the blocksize divides the plaintext evenly.
 *          For CTR mode, this is the same size as the plaintext.
 * @note @b plaintext and @b ciphertext are aliasable.
 * @note Encrypt is streamable, such that encrypt(msg1) + encrypt(msg2) is functionally identical to encrypt(msg1+msg2)
 * with the exception of intervening padding in CBC mode.
 * @note Once a  context is used for encryption, a stateful flag is set preventing the same context from being used for decryption.
 * @returns AES_OK if success, non-zero if failed. See aes_error_t.
 */
aes_error cryptx_aes_encrypt(
					const struct cryptx_aes_ctx* context,
					const void* plaintext,
					size_t len,
					void* ciphertext);

/******************************************************
 * @brief General-Purpose AES Decryption
 * @param ctx Pointer to AES cipher context.
 * @param ciphertext Pointer to data to decrypt.
 * @param len Length of data at @b ciphertext to decrypt.
 * @param plaintext Pointer to buffer to write decryped data to.
 * @note @b plaintext and @b ciphertext are aliasable.
 * @note Decrypt is streamable, such that decrypt(msg1) + decrypt(msg2) is functionally identical to decrypt(msg1+msg2)
 * with the exception of intervening padding in CBC mode.
 * @note Once a context is used for decryption, a stateful flag is set preventing the same context from being used for encryption.
 * @returns AES_OK if success, non-zero if failed. See aes_error_t.
 */
aes_error cryptx_aes_decrypt(
					const struct cryptx_aes_ctx* context,
					const void* ciphertext,
					size_t len,
					void* plaintext);


/*
 RSA Public Key Encryption
 
 Public key encryption is a form of asymmetric encryption.
 This means that a key only works in one direction, and both parties need a public key
 and a private key. The private key is used to decrypt a message and the public key is
 used to encrypt.
 In RSA, the public and private keys are modular inverses of each other, such that:
 encrypted = message ** public exponent % public key, and
 message = encrypted ** private exponent % private modulus
 ** means power, % means modulus
 
 65537 (and a few other Fermat primes) are commonly used as public exponents.
 The public key (modulus) is sent in the clear and is known to to everyone.
 The cryptographic strength of RSA comes from the difficulty of factoring the modulus.
 Asymmetric encryption is generally VERY slow. Using even RSA-1024 on the TI-84+ CE will
 take several seconds. For this reason, you usually do not use RSA for sustained encrypted
 communication. Use RSA to share a symmetric key, and then use AES for future messages.
 
 */

/******************
 * @enum rsa_error_t
 * RSA error codes
 */
typedef enum {
	RSA_OK,                         /**< RSA encryption completed successfully */
	RSA_INVALID_ARG,                /**< RSA encryption failed, bad argument */
	RSA_INVALID_MSG,                /**< RSA encryption failed, bad msg or msg too long */
	RSA_INVALID_MODULUS,            /**< RSA encryption failed, modulus invalid */
	RSA_ENCODING_ERROR              /**< RSA encryption failed, OAEP encoding error */
} rsa_error;


/******************
 * @def RSA_MODULUS_MAX
 * Defines the largest possible byte length for a modulus
 * supported by this library.
 */
#define RSA_MODULUS_MAX		256
/*****************************************************
 * @brief RSA Encryption
 *
 * Performs an in-place RSA encryption of a message
 * over a public modulus \b pubkey and a public exponent, 65537
 * OAEP encoding of the input message is performed automatically.
 *
 * @param msg Pointer to a message to encrypt using RSA.
 * @param msglen The length of the message @b msg.
 * @param ciphertext Pointer a buffer to write the ciphertext to.
 * @param pubkey Pointer to a public key to use for encryption.
 * @param keylen The length of the public key (modulus) to encrypt with.
 * @param oaep_hash_alg The numeric ID of the hashing algorithm to use within OAEP encoding.
 *      See @b hash_algorithms.
 * @note The size of @b ciphertext and @b keylen must be equal.
 * @note The @b msg will be encoded using OAEP before encryption.
 * @note msg and pubkey are both treated as byte arrays.
 * @return rsa_error_t
 */
rsa_error cryptx_rsa_encrypt(
					const void* msg,
					size_t msglen,
					void* ciphertext,
					const void* pubkey,
					size_t keylen,
					uint8_t oaep_hash_alg);


/*
 Elliptic Curve Diffie-Hellman (ECDH)
 
 Elliptic Curve Diffie-Hellman is a variant on the Diffie-Hellman secret exchange protocol
 that uses elliptic curve point multiplication instead of standard modular exponentiation.
 In this variant of Diffie-Hellman you provide a private key initialized with securely random
 bytes (or pass a random-fill function to the keygen function) and that private key acts as a
 scalar for point multiplication. A base point (G) defined by the curve specification is multiplied
 by the scalar, yielding another point on the curve, (x, y) that is the public key. This public key
 can be sent in the clear to another party. Both the private key, (x, y), and G are very large integers
 in the order of the degree of the selected curve. This means that the curve defines the bitwise security
 level of the encryption. The key generation can be represented in formula like so:
 
 Alice:	aP * G = aU			<== aP = alice private key, G = base point on curve, aU = alice public key
 Bob:	bP * G = bU			<== bP = bob private key, G = base point on curve, bU = bob public key
 
 To compute a shared secret, both parties take their own private key and use it as a scalar to
 perform point multiplication on the other party's public key. Before doing so, each endpoint should
 validate the public key by confirming that it is (1) non-zero, and (2) a point on the curve.
 Performing the point multiplication should yield the same secret for both parties.
 Once the secret is computed, it should be passed to a KDF or a cryptographic hash to generate a
 key for symmetric encryption. The secret derivation can be represented in formula like so:
 
 Alice:
	aP * bU = S,		<== aP = alice private key, bU = bob public key, S = shared secret
	K = KDF(S)		 	<== K = symmetric encryption key, KDF = some key derivation function
 Bob:
	bP * aU = S,		<== bP = bob private key, bU = alice public key, S = shared secret
	K = KDF(S)			<== K = symmetric encryption key, KDF = some key derivation function
 
 As with RSA, ECDH is not intended to be used for sustained encrypted communication. It is another method
 of exchanging a secret. Once the secret is negotiated (either via RSA or ECDH), use that secret to set up
 an AES session and use AES for sustained encryption. It is much faster.
 
 This ECDH implementation uses the NIST K-233 (sect233k1) curve, a binary polynomial with degree 233.
 It uses a key size of up to 233 bits (though this implementation encourages the use of 29 bytes (232 bits).
 This spec provides roughly the same security level as a 2048 bit RSA key.
 */

/**************************************************
 * @def ECDH\_PRIVKEY\_SIZE
 * Defines the byte length of the ECDH private key.
 * @note This is defined as 32 for compatibility with other libraries.
 * However, all points worked with do not exceed 233 bits due to the
 * particulars of finite field arithmetic. The private key will be trimmed
 * to not exceed 233 bits.
 */
#define ECDH_PRIVKEY_SIZE		29

/*********************************************
 * @def ECDH\_PUBKEY\_SIZE
 * Defines the byte length of the ECDH public key.
 * @note This is twice the length of the private key.
 */
#define ECDH_PUBKEY_SIZE		(ECDH_PRIVKEY_SIZE<<1)

struct cryptx_ecdh_ctx {
	uint8_t privkey[ECDH_PRIVKEY_SIZE];
	uint8_t pubkey[ECDH_PUBKEY_SIZE];
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
} ecdh_error;

/************************************************************************
 * @brief ECDH Generate Public Key.
 * If @b randfill is provided, generates a random private key
 * 29 bytes long (largest byte length less than 233 bits). Otherwise
 * assumes that the key was generated by the user.
 * Then generates the public key given the private key and generator G.
 * @param ctx Pointer to an ECDH context containing reserved public and private key buffers.
 * @param randfill Pointer to a function that can fill a buffer with random bytes.
 * @note If @b randfill is @b NULL it is assumed that you have initialized the key with
 * random bytes yourself. If you do not know what you are doing @b DO_NOT_DO_THIS.
 * Just pass @b csrand_fill to the @b randfill parameter.
 * @note Output public key is a point on the curve expressed as two 32-byte coordinates
 * encoded in little endian byte order and padded with zeros if needed. You may have to
 * deserialize the key and then serialize it into a different format to use it with
 * some encryption libraries.
 */
ecdh_error cryptx_ecdh_keygen(struct cryptx_ecdh_ctx* context, bool (*randfill)(void *buffer, size_t size));

/*************************************************
 * @brief ECDH Compute Shared Secret
 * Given local private key and remote public key, generate a secret.
 * @param ctx Pointer to context containing local private key.
 * @param rpubkey Pointer to remote public key.
 * @param secret Pointer to buffer to write shared secret to.
 * @note @b secret must be at least @b ECDH_PUBKEY_SIZE bytes.
 * @note Output secret is a point on the curve expressed as two 32-byte coordinates
 * encoded in little endian byte order and padded with zeros if needed. You may have to
 * deserialize the secret and then serialize it into a different format for compatibility with
 * other encryption libraries.
 * @note It is generally not recommended to use the computed secret as an encryption key as is.
 * It is preferred to pass the secret to a KDF or a cryptographic primitive such as a hash function and use
 * that output as your symmetric key.
 */
ecdh_error cryptx_ecdh_secret(const struct cryptx_ecdh_ctx *context, const uint8_t *rpubkey, uint8_t *secret);


/*
 #### INTERNAL FUNCTIONS ####
 For advanced users only!!!
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
void cryptx_internal_aes_ecb_encrypt(const void *block_in, void *block_out, aes_ctx *ks);

/*****************************************************
 * @brief AES single-block ECB mode decryption function
 * @param block_in Block of data to encrypt.
 * @param block_out Buffer to write encrypted block of data.
 * @param ks AES key schedule context to use for encryption.
 * @note @b block_in and @b block_out are aliasable.
 * @warning ECB mode encryption is insecure (see many-time pad vulnerability).
 *     Use ECB-mode block encryptors as a constructor for custom cipher modes only.
 */
void cryptx_internal_aes_ecb_decrypt(const void *block_in, void *block_out, aes_ctx *ks);

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

/*****************************************************
 * @brief Probabilistic Sisgnature Scheme (PSS) encoder for RSA
 * @param plaintext Pointer to the plaintext message to encode.
 * @param len Lengfh of the message to encode.
 * @param encoded Pointer to buffer to write encoded message to.
 * @param modulus_len Length of the RSA modulus to encode for.
 * @param salt A nonce that can be passed to the encryption scheme. Pass NULL to generate internally.
 * @param hash_alg The numeric ID of the hashing algorithm to use. See @b hash_algorithms.
 * @return Boolean | True if encoding succeeded, False if encoding failed.
 * @note Generally, to encode a message, pass NULL as salt.
 *      To verify a message, pass a pointer to the salt field in the message you are looking to verify.
 */
bool cryptx_internal_rsa_pss_encode(
			const void *plaintext,
			size_t len,
			void *encoded,
			size_t modulus_len,
			void *salt,
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
bool cryptx_internal_gf2_tobytes(void *dest, const uint8_t* gf2_bigint, bool big_endian);

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
 * @typedef ecc\_point
 * Defines a point to be used for elliptic curve point arithmetic.
 */

struct cryptx_ecc_point { uint8_t x[GF2_INTLEN]; uint8_t y[GF2_INTLEN]; }

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
