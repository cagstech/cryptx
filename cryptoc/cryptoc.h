/**
 *	@file cryptoc.h
 *	@brief	Cryptography Library for the TI-84+ CE
 *
 *	Industry-Standard Cryptography for the TI-84+ CE
 *	- Secure Random Number Generator (SRNG)
 *	- cipher_aes
 *	- cipher_rsa
 *
 *	@author Anthony @e ACagliano Cagliano
 *	@author Adam @e beck Beckingham
 *	@author commandblockguy
 */

#ifndef CRYPTOC_H
#define CRYPTOC_H

/*
 Cryptographically-Secure Random Number Generator (CS-RNG)
 
 Many of the psuedorandom number generators (PRNGs) you find in computers and
 even the one within the C toolchain for the CE are insecure for cryptographic
 purposes. They produce statistical randomness, but the state is generally seeded
 using a value such as rtc_Time(). If an adversary reconstructs the seed, every
 output of the PRNG becomes computable with little effort. These types of PRNGs
 are called deterministic algorithms--given the input, the output is predictable.
 These PRNGs work for games and other applications where the illusion of randomness
 is sufficient, but they are not safe for cryptography.
 
 A secure PRNG is an random number generator that is not only statistically random, but
 also passes the next-bit and state compromise tests. The _next-bit test_ is defined like so:
 given the prior output of the PRNG (bits 0=>i), the next bit (i+1) of the output cannot be
 predicted by a polynomial-time statistical test with a probability non-negligibly greater than 50%.
 In simpler terms, a secure PRNG must be unpredictable, or "entropic".
 The _state compromise test_ means that an adversary gaining knowledge of the initial state of
 the PRNG does not gain any information about its output.
 
 The SRNG previded by HASHLIB solves both tests like so:
 (next-bit)
 <>  The SRNG's output is derived from a 119-byte entropy pool created by reading
 data from the most entropic byte located within floating memory on the device.
 <>  The "entropic byte" is a byte containing a bit that that, out of 1024 test reads,
 has the closest to a 50/50 split between 1's and 0's.
 <>  The byte containing that bit is read in xor mode seven times per byte to offset
 any hardware-based correlation between subsequent reads from the entropic byte.
 <>  The entropy pool is then run through a cryptographic hash to spread that entropy
 evenly through the returned random value.
 <>  The SRNG produces 96.51 bits of entropy per 32 bit number returned.
 <>  Assertion: A source of randomness with sufficient entropy passed through a cryptographic hash
 will produce output that passes all statistical randomness tests as well as the next-bit test.
 (state compromise)
 <>  The entropy pool is discarded after it is used once, and a new pool is
 generated for the next random number.
 <>  ^ This means that the prior state has no bearing on the next output of the PRNG.
 <>  The SRNG destroys its own state after the random number is generated so that
 the state used to generate it does not persist in memory.
 
 *   Due to the derivation of entropy from subtle variations in the electrical state of
 unmapped memory, this SRNG can also be considered a _hardware-based RNG_ (HWRNG).
 */

/**
 * @brief Initializes the crypto-safe random number generator.
 *
 * The SRNG is initialized by polling the 512-bytes from address 0xD65800 to 0xD66000.
 * This region consists of unmapped memory that contains bus noise.
 * Each bit in that region is polled 1024 times and the address with the bit that is the least biased is selected.
 * That will be the byte the SRNG uses to generate entropy.
 * @return boolean: True if a sufficient entropy source was identified. False otherwise.
 * @note Catch and respond to a @b False return from this function. Do not proceed with generating nonces
 *      and encryption keys without ensuring the initialization was successful.
 * @note It may be a good idea to call this function in any program that uses hashlib functions for good measure.
 * @note The SRNG is not reliably entropic on CEmu, due to the emulation of bus noise using a deterministic RNG.
 -------------------------------------------*/
bool csrand_init(void);

/**
 * @brief Generates a random 32-bit number.
 *
 * - Populates a 119-byte entropy pool by xor'ing 7 distinct reads from the unmapped address together per byte.
 * - Hashes the entropy pool using SHA-256.
 * - Breaks the SHA-256 hash into 8-byte blocks, then xor's all 8 bytes each block together, leaving four (4) composite bytes.
 * @return A psuedo random 32-bit integer.
 -------------------------------------------------------------*/
uint32_t csrand_get(void);

/**
 * @brief Fills a buffer to size with random bytes.
 *
 * @param buffer A pointer to a buffer to write random data to.
 * @param size Number of bytes to write.
 * @note @b buffer must be at least @b size bytes large.
 ---------------------------------------------------------------------------------*/
bool csrand_fill(void* buffer, size_t size);

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

/**
 * @typedef aes_ctx
 * Stores AES cipher configuration data, s.t. passing it to aes_encrypt/decrypt provides
 * data about cipher mode, padding mode (CBC), and counter length (CTR) without
 * requiring any additional arguments.
 -------------------------------------------------------------------------------------------------------------------*/

typedef struct _aes_cbc { uint8_t padding_mode; } aes_cbc_t;
typedef struct _aes_ctr {
	uint8_t counter_pos_start; uint8_t counter_len;
	uint8_t last_block_stop; uint8_t last_block[16]; } aes_ctr_t;

typedef struct _aes_ctx {
	uint24_t keysize;                       /**< the size of the key, in bits */
	uint32_t round_keys[60];                /**< round keys */
	uint8_t iv[16];                         /**< IV state for next block */
	uint8_t ciphermode;                     /**< selected operational mode of the cipher */
	union {
		aes_ctr_t ctr;                      /**< metadata for counter mode */
		aes_cbc_t cbc;                      /**< metadata for cbc mode */
	} mode;
	uint8_t op_assoc;                       /**< state-flag indicating if context is for encryption or decryption*/
} aes_ctx;

/**
 * @enum aes_cipher_modes
 * Supported AES cipher modes
 * Defaults to AES_MODE_CBC if unset.
 * @see aes_init
 -------------------------------------------*/
enum aes_cipher_modes {
	AES_MODE_CBC,       /**< selects CBC mode */
	AES_MODE_CTR        /**< selects CTR mode */
};

/**
 * @enum aes_padding_schemes
 * Supported AES padding schemes
 * Defaults to PAD_PKCS7 if unset.
 * @see aes_init
 ------------------------------------------------*/
enum aes_padding_schemes {
	PAD_PKCS7,                  /**< PKCS#7 padding | DEFAULT */
	PAD_DEFAULT = PAD_PKCS7,	/**< selects the scheme marked DEFAULT.
								 Using this is recommended in case a change to the standards
								 would set a stronger padding scheme as default */
	PAD_ISO2 = 4,               /**< ISO-9797 M2 padding */
};

/**
 * @define AES_CTR_NONCELEN
 * Only has an effect when cipher is initialized to CTR mode.
 * Sets the length of the fixed prefix of the iniitalization vector.
 * Vaiid lengths: 1 <= len < block size
 * The prefix does not change as the counter increments.
 -----------------------------------------------------------------------------------*/
#define AES_CTR_NONCELEN(len)   ((0x0f & len)<<4)

/**
 * @define AES_CTR_COUNTERLEN
 * Only has an effect when cipher is initialized to CTR mode.
 * Sets the length of the counter portion of the initialization vector.
 * Valid lengths: 1 <= len < block size
 * The counter increments by 1 with every block encrypted.
 * @b AES_CTR_COUNTERLEN and @b AES_CTR_NONCELEN work together to
 * define the behavior of the IV block in CTR mode. Defining the nonce as a field of
 * length N, the counter as a field of length C, and the suffix as a field of length S, the
 * IV behavior is defined as:
 * [ N-byte NONCE ] [ C-byte COUNTER ] [ S-byte SUFFIX].
 * The nonce and suffix are fixed portions of the IV.
 * The suffix will only exist if you explicitly define a length for the counter and the nonce
 * and they add up to less than the IV size.
 * Some libraries refer to the nonce as a "prefix"..
 --------------------------------------------------------------------*/
#define AES_CTR_COUNTERLEN(len) ((0x0f & len)<<8)


/**
 * @def AES_BLOCKSIZE
 * Defines the blocksize of the AES cipher.
 -----------------------------------------------*/
#define AES_BLOCKSIZE	16

/**
 * @def AES_IVSIZE
 * Defines the length of the AES initalization vector (IV).
 -------------------------------------------------------------------------*/
#define AES_IVSIZE		AES_BLOCKSIZE

/**
 * @def aes_outsize()
 *
 * Defines a macro to return the size of an AES ciphertext given a plaintext length.
 * Does not include space for an IV-prepend. See @b aes_extoutsize(len) for that.
 *
 * @param len The length of the plaintext.
 ------------------------------------------------------------*/
#define aes_outsize(len) \
((((len)%AES_BLOCKSIZE)==0) ? (len) + AES_BLOCKSIZE : (((len)>>4) + 1)<<4)

/**
 * @def aes_extoutsize()
 *
 * Defines a macro to return the size of an AES ciphertext with with an extra block added for the IV.
 *
 * @param len The length of the plaintext.
 ------------------------------------------------------------*/
#define aes_extoutsize(len) \
(aes_outsize((len)) + AES_IVSIZE)

/**
 * @enum aes_error_t
 * AES Error Codes
 * (returned by AES functions)
 -----------------------------------------*/
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
 * @param ctx Pointer to an AES cipher context to initialize..
 * @param key Pointer to an 128, 192, or 256 bit key to load into the AES context.
 * @param keylen The size, in bytes, of the key to load.
 * @param iv Initialization vector, a buffer equal to the block size that is pseudo-random.
 * @param flags A series of flags to configure the AES context with. This is the bitwise OR of any non-default cipher options. Ex:
 *      @code
 *          aes_init(ctx, key, sizeof key, iv, AES_MODE_CTR | AES_CTR_COUNTERLEN(4));
 *          // this sets CTR mode and sets the counter to 4 bytes (32 bits)
 *          // since the nonce length is 8 bytes by default, this actually means the IV format is:
 *          // [nonce 8 bytes] [counter 4 bytes] [suffix 4 bytes]
 *      @endcode
 * @note Do not edit a context manually. You may corrupt the cipher state.
 * @note Contexts are not bidirectional due to being stateful. If you need to process both encryption and decryption, initialize seperate contexts
 *      for encryption and decryption. Both contexts will use the same key, but different initialization vectors.
 * @warning It is recommended to cycle your key after encrypting 2^64 blocks of data with the same key.
 * @warning Do not manually edit the @b ctx.mode field of the context structure. This will break the cipher configuration.
 *          If you want to change cipher modes, do so by calling @b aes_init again.
 * @warning AES-CBC and CTR modes ensure confidentiality but do not guard against tampering. AES-OCB/GCM are a bit computationallty-intensive
 *          for this platform, but HASHLIB provides hash and hmac functions in their stead. HMAC is generally more secure for this purpose.
 *          If you want a truly secure scheme, always append an HMAC to your message and use an application secret or unique key
 *          generated using a CSRNG to key the HMAC at both endpoints.
 * @return AES_OK if success, non-zero if failed. See aes_error_t.
 -----------------------------------------------------------------------------------------------*/
aes_error_t aes_init(
				aes_ctx* ctx,
				const void* key,
				size_t keylen,
				const void* iv,
				uint24_t flags);

/**
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
 ---------------------------------------------------------------------------------------------*/
aes_error_t aes_encrypt(
					const aes_ctx* ctx,
					const void* plaintext,
					size_t len,
					void* ciphertext);

/**
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
 ----------------------------------------------------------------------------------------------*/
aes_error_t aes_decrypt(
					const aes_ctx* ctx,
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

/**
 * @enum rsa_error_t
 * RSA Encryption Error Codes
 -------------------------------------------*/
typedef enum {
	RSA_OK,                         /**< RSA encryption completed successfully */
	RSA_INVALID_ARG,                /**< RSA encryption failed, bad argument */
	RSA_INVALID_MSG,                /**< RSA encryption failed, bad msg or msg too long */
	RSA_INVALID_MODULUS,            /**< RSA encryption failed, modulus invalid */
	RSA_ENCODING_ERROR              /**< RSA encryption failed, OAEP encoding error */
} rsa_error_t;

/**
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
 ---------------------------------------------------------------*/
rsa_error_t rsa_encrypt(
					const void* msg,
					size_t msglen,
					void* ciphertext,
					const void* pubkey,
					size_t keylen,
					uint8_t oaep_hash_alg);


#ifdef CRYPTOC_ENABLE_ADVANCED_MODE

/*
 #### INTERNAL FUNCTIONS ####
 For advanced users only!!!
 
 To enable advanced mode place the directive:
 #define CRYPTOC_ENABLE_ADVANCED_MODE
 above any inclusion of this header file.
 
 If you know what you are doing and want to implement your own cipher modes,
 or signature algorithms, a few internal functions are exposed here.
 */

/**
 * @brief AES single-block ECB mode encryption function
 * @param block_in Block of data to encrypt.
 * @param block_out Buffer to write encrypted block of data.
 * @param ks AES key schedule context to use for encryption.
 * @note @b block_in and @b block_out are aliasable.
 * @warning ECB mode encryption is insecure (see many-time pad vulnerability).
 *     Use ECB-mode block encryptors as a constructor for custom cipher modes only.
 -----------------------------------------------------------------------------------------------------------------------------*/
void aes_ecb_unsafe_encrypt(const void *block_in, void *block_out, aes_ctx *ks);

/**
 * @brief AES single-block ECB mode decryption function
 * @param block_in Block of data to encrypt.
 * @param block_out Buffer to write encrypted block of data.
 * @param ks AES key schedule context to use for encryption.
 * @note @b block_in and @b block_out are aliasable.
 * @warning ECB mode encryption is insecure (see many-time pad vulnerability).
 *     Use ECB-mode block encryptors as a constructor for custom cipher modes only.
 -----------------------------------------------------------------------------------------------------------------------------*/
void aes_ecb_unsafe_decrypt(const void *block_in, void *block_out, aes_ctx *ks);

/**
 * @brief Optimal Asymmetric Encryption Padding (OAEP) encoder for RSA
 * @param plaintext Pointer to the plaintext message to encode.
 * @param len Lengfh of the message to encode.
 * @param encoded Pointer to buffer to write encoded message to.
 * @param modulus_len Length of the RSA modulus to encode for.
 * @param auth An authentication string to include in the encoding. Can be NULL to omit.
 * @param hash_alg The numeric ID of the hashing algorithm to use. See @b hash_algorithms.
 * @return Boolean | True if encoding succeeded, False if encoding failed.
 * @note @b plaintext and @b encoded are aliasable.
 ----------------------------------------------------------------*/
bool oaep_encode(
			const void *plaintext,
			size_t len,
			void *encoded,
			size_t modulus_len,
			const uint8_t *auth,
			uint8_t hash_alg);

/**
 * @brief OAEP decoder for RSA
 * @param encoded Pointer to the plaintext message to decode.
 * @param len Lengfh of the message to decode.
 * @param plaintext Pointer to buffer to write decoded message to.
 * @param auth An authentication string to include in the encoding. Can be NULL to omit.
 * @param hash_alg The numeric ID of the hashing algorithm to use. See @b hash_algorithms.
 * @return Boolean | True if encoding succeeded, False if encoding failed.
 * @note @b plaintext and @b encoded are aliasable.
 ------------------------------------------------------------*/
bool oaep_decode(
			const void *encoded,
			size_t len,
			void *plaintext,
			const uint8_t *auth,
			uint8_t hash_alg);

/**
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
 -------------------------------------------------------------*/
bool pss_encode(
			const void *plaintext,
			size_t len,
			void *encoded,
			size_t modulus_len,
			void *salt,
			uint8_t hash_alg);

/**
 * @brief Modular Exponentiation function for RSA (and other implementations)
 * @param size The length, in bytes, of the @b base and @b modulus.
 * @param base Pointer to buffer containing the base, in bytearray (big endian) format.
 * @param exp A 24-bit exponent.
 * @param mod Pointer to buffer containing the modulus, in bytearray (big endian) format.
 * @note For the @b size field, the bounds are [0, 255] with 0 actually meaning 256.
 * @note @b size must not be 1.
 * @note @b exp must be non-zero.
 * @note @b modulus must be odd.
 ----------------------------------------------------------*/
void powmod(
		uint8_t size,
		uint8_t *restrict base,
		uint24_t exp,
		const uint8_t *restrict mod);


#endif

#endif
