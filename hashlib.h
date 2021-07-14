#ifndef HASHLIB_H
#define HASHLIB_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// INCLUDE FILE FOR HASHLIB

// ###################################################
// ## Context Definitions for Hashes and Encryption ##
// ###################################################

typedef struct _sha256_ctx {
	uint8_t data[64];
	uint8_t datalen;
	uint8_t bitlen[8];
	uint32_t state[8];
} sha256_ctx;

typedef struct {
    uint24_t keysize;
    uint32_t round_keys[60];
} aes_ctx;


// ###############################
// ##### DEFINES and EQUATES #####
// ###############################

/* SHA Size Defines */
#define SHA256_DIGEST_LEN   32
#define SHA256_HEXSTR_LEN   (SHA256_DIGEST_LEN<<1) + 1      // 2x digest len, plus null
#define SHA256_MBUFFER_LEN	(64 * 4)

/* AES Size Defines */
#define AES_BLOCKSIZE	16
#define AES_IV_SIZE		AES_BLOCKSIZE
#define AES_MAC_SIZE	AES_BLOCKSIZE

/* AES Padded Size - Data only */
#define hashlib_AESPaddedSize(len) \
	((((len)%AES_BLOCKSIZE)==0) ? len + AES_BLOCKSIZE : ((len>>4) + 1)<<4)

/* AES Ciphertext Size - Padded Size + IV Size */
#define hashlib_AESCiphertextSize(len)	\
	(hashlib_AESPaddedSize((len)) + AES_IV_SIZE)
	
/* AES Ciphertext + MAC Size - Padded Size + IV Size + MAC Size */
#define hashlib_AESCiphertextMACSize(len)	\
	(hashlib_AESCiphertextSize((len)) + AES_MAC_SIZE)

/* Returns the OAEP-padded size of an RSA plaintext - simply equal to modulus size */
#define hashlib_RSAPaddedSize(modulus_len)   (modulus_len)

/*
	## Fast Memory Defines ##
	
	You can use these defines to store various contexts and memory buffers into
	the region of fast memory (cursorImage) so that they run faster.
	
	* NOTE This region gets clobbered by LIBLOAD
	If Libload runs, any contexts in use will be destroyed
*/
#define hashlib_Sha256MBufferFast	((uint8_t*)0xE30800)
#define hashlib_Sha256ContextFast	((sha256_ctx*)(hashlib_Sha256MBufferFast + 64*4))
// #define hashlib_RSAVintBufferFast	((vint_t*)(hashlib_Sha256ContextFast + sizeof(sha256_t)))
#define hashlib_AESKeyScheduleBufferFast	((aes_ctx*)(hashlib_RSAVintBuffer + 257))


// ###################################
// ##### MISCELLANEOUS FUNCTIONS #####
// ###################################

/*
    Erases the data in a context, ensuring that no traces of cryptographic arithmetic remain.
    
    # Inputs #
    <> ctx = pointer to an arbitrary context type from this library
    <> len = length in bytes to zero
    
    Example: hashlib_EraseContext(&sha1_ctx, sizeof(sha1_ctx));
    * It is advised to call this on every context declared in your program before exiting or freeing that region
 */
void hashlib_EraseContext(void *ctx, size_t len);


/*
    A helper macro that returns a hashlib context (see defines above)
    Can also be used to malloc buffers for encryption/decryption/padding/etc.
 */
#define hashlib_AllocContext(size)		malloc((size))


/*
	Helper macros to generate AES keys for the 3 possible keylengths.
	
	# Inputs #
	<> buffer = A pointer to a buffer to write the key to
	
	# Outputs #
	An AES key of the correct length is written to buffer
 */
#define hashlib_AESKeygen128(buffer)	hashlib_RandomBytes((buffer), (128>>3))
#define hashlib_AESKeygen192(buffer)	hashlib_RandomBytes((buffer), (192>>3))
#define hashlib_AESKeygen256(buffer)	hashlib_RandomBytes((buffer), (256>>3))


/*
    Compares the pointed buffers digest1 and digest2 for size len.
    This function is resistant to timing attacks.
    
    # Input #
    <> digest1 = pointer to first buffer to compare
    <> digest2 = pointer to second buffer to compare
    <> len = number of bytes to compare
 */
hashlib_CompareDigest(const uint8_t* digest1, const uint8_t* digest2, size_t len);

/*
    Pads input data for AES encryption according to a selection of standard padding schemes.
    
    # Inputs #
    <> plaintext = pointer to buffer containing data to pad
    <> len = size of data to pad, in bytes (real size, not block-aligned size)
    <> outbuf = pointer to buffer large enough to hold padded data (see macros below)
    <> schm = padding scheme to pad with (see enumerations below)
 */
 
size_t hashlib_AESPadMessage(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* outbuf,
    uint8_t schm);
    
/*
    Reverses the padding on an AES plaintext according to a selection of standard padding schemes.
    
    # Inputs #
    <> plaintext = pointer to buffer containing data to pad
    <> len = size of data to pad, in bytes (real size, not block-aligned size)
    <> outbuf = pointer to buffer large enough to hold padded data (see macros below)
    <> schm = padding scheme to pad with (see enumerations below)
    
    * If input SCHM mode is SCHM_ANSIX923, size returned is the same as input size
        you will need to maintain your own expected unpadded data length
 */
size_t hashlib_AESStripPadding(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* outbuf,
    uint8_t schm);
    
/*
    Pads input data in an RSA plaintext according to the Optimal Asymmetric Encryption Padding (OAEP) scheme.
    
    |---------|--------------------------|-----------------|
    | Message | 0x00, 0x00,... (Padding) | Salt (16 bytes) |    == modulus len
    |---------|--------------------------|-----------------|
                         |                        |
                        XOR  <------SHA-256--------
                         |                        |
                         |-------SHA-256-------> XOR
                         |                        |
    |------------------------------------|-----------------|
    |     Encoded Message + Padding      |  Encoded Salt   |
    |------------------------------------|-----------------|
    
    # Inputs #
    <> plaintext = pointer to buffer containing data to pad
    <> len = size of data to pad, in bytes
    <> outbuf = pointer to buffer large enough to hold padded data (see macros below)
    <> modulus_len = the bit-length of the modulus, used to determine the padded message length
 */
size_t hashlib_RSAPadMessage(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* outbuf,
    size_t modulus_len);
    
/*
    Reverses the padding on an RSA plaintext according to the OAEP padding scheme.
    
    # Inputs #
    <> plaintext = pointer to buffer containing data to pad
    <> len = size of data to pad, in bytes (real size, not block-aligned size)
    <> outbuf = pointer to buffer large enough to hold padded data (see macros below)
*/
size_t hashlib_RSAStripPadding(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* outbuf);
    

enum _padding_schemes {
    SCHM_DEFAULT,
    SCHM_PKCS7,         // Pad with padding size        |   (AES)   *Default*
    SCHM_ISO_M2,        // Pad with 0x80,0x00...0x00    |   (AES)
    SCHM_ANSIX923,      // Pad with randomness          |   (AES)
};

/*
####################################################
### Secure Psuedorandom Number Generator (SPRNG) ###
####################################################

    This PRNG utilizes an internal state that is controlled by the lib.
    While users can read from it and add entropy to it manually, they cannot modify it
        directly.
    The CSPRNG consists of a single `volatile uint8_t*`, internally called `eread` as well as
        a 128-byte entropy pool.
   
    ### Polling for Most Entropic Bit ###
        * hashlib_SPRNGInit();
        <> For each byte in the memory region affected by bus noise, read each bit 1024 times
        <> If the bit was set, increment a counter
        <> Set initial minimum deviation to +/- 1/4 of the read count from absolute 50/50 split.
            For example, out of 1024 tests, a bit is considered to be of sufficient entropy
            if it deviates from 256-768 1's, with values closer to 512 being preferred.
        <> Select the byte with the bit that deviates from 512 the least.
    
    ** hashlib_SPRNGInit() will return NULL if it was unable to find a bit of sufficient
        entropy on your device. While this is unlikely, if this does occur, it may help to run it a few times. Like so:
        
        `for(uint8_t ctr = 5; ctr>0 && !hashlib_SPRNGInit(); ctr--);`
        
    ### Generation of Random Numbers ###
        * hashlib_SPRNGRandom()
        <> Allocate but do not assign a uint32_t. This will fill the value with garbage.
        <> Read from eread 4 times, XOR'ing each read with 8 bits of our partial rand.
        <> SHA-256 hash the entropy pool, then XOR the hash with the partial rand in 4-byte blocks.
        <> Call hashlib_CSPRNGAddEntropy() to scramble the state
        <> Return the uint32_t
        
    * hashlib_SPRNGAddEntropy() may be called by the user in a loop to provide more dynamic entropy
        than this lib can provide by default
        
    * This SPRNG passes all dieharder tests for a sample size of 16,384 bytes or more *
*/


//  Initialize the cryptographic RNG by finding the byte of most entropy on the current device
//  Returns the address selected as a (void*)
void* hashlib_SPRNGInit(void);

//  Reads from byte selected 128 times, XORing new reads with existing data in the entropy pool
bool hashlib_SPRNGAddEntropy(void);
 
//  Returns a 32-bit integer, derived from the entropy pool
uint32_t hashlib_SPRNGRandom(void);


/*
    Fills a buffer to (size) with random bytes using the internal CSPRNG
    
    # Inputs #
    <> buffer = buffer to fill with random data
    <> size = how many bytes to write
    
    # Outputs #
    <> True if no errors encountered
    <> False if buffer was NULL or size was 0
    ** It is planned to make this compatible with beck's BIGINT lib
 */
bool hashlib_RandomBytes(uint8_t *buffer, size_t size);


// ####################
// ### SHA-256 HASH ###
// ####################

/*
    Init Context for SHA-256

    # Inputs #
    <> ctx = pointer to an sha256_ctx
    <> mbuffer = pointer to 64*4 bytes of temporary ram used internally by hashlib_Sha256Update. It may be 0 if it's been set before, and if the memory it's been set to is still valid.
    ** SHA-256 will be invalid if this function is not called before hashing
    ** contexts are specific to a hash-stream. If there is another block of data you
        want to hash concurrently, you will need to init a new context
*/
void hashlib_Sha256Init(sha256_ctx *ctx, uint32_t *mbuffer);
/*
    Update Context for SHA-256

    # Inputs #
    <> ctx = pointer to an SHA256_CTX
    <> buf = ptr to a block of data to hash
    <> len = size of the block of data to hash
    ** Remember, if hashlib_Sha256Init is not called first, your hash will be wrong
*/
void hashlib_Sha256Update(sha256_ctx *ctx, const uint8_t *buf, uint32_t len);

/*
    Finalize Context and Render Digest for SHA-256

    # Inputs #
    <> ctx = pointer to an SHA256_CTX
    <> digest = pointer to buffer to write digest
*/
void hashlib_Sha256Final(sha256_ctx *ctx, uint8_t *digest);

/*
    One-Shot SHA-256 Computation

    # Inputs #
    <> buf = pointer to data to hash
    <> len = length of data to hash
    <> digest = pointer to buffer to write digest
*/

// ##########################################
// ### ADVANCED ENCRYPTION STANDARD (AES) ###
// ##########################################
// 32-bit implementation
// 128, 192, or 256 bit keys
// 10, 12, or 14 rounds
// Cipher Block Chaining Mode only
        
/*
    AES Import Key
    ** The key can be a user-generated byte sequence, ranging from 32 bits to 448 bits
    
    # Inputs #
    <> key = pointer to a 128, 192, or 256 bit key
    <> ks = pointer to an AES key schedule context
    <> keysize = size of the key, in bits. Valid arguments are: 128, 192, and 256.
     */
void hashlib_AESLoadKey(const uint8_t* key, const aes_ctx* ks, size_t keysize);

/*
    AES-CBC Encrypt
    
    # Inputs #
    <> plaintext = pointer to data to encrypt (pass through padding helper func first)
    <> len = size of data to encrypt
    <> ciphertext = pointer to buffer to write encrypted output
    <> ks = pointer to ks schedule initialized with AESLoadKey
    <> iv = pointer to initialization vector (psuedorandom 16-byte field)
 */
bool hashlib_AESEncrypt(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* ciphertext,
    const aes_ctx* ks,
    const uint8_t* iv);
    
/*
    <> ciphertext = pointer to data to decrypt
    <> len = size of data to decrypt
    <> plaintext = pointer to buffer to write decompressed output
    <> ks = pointer to initialized key schedule
    <> iv = pointer to initialization vector 
 */
size_t hashlib_AESDecrypt(
    const uint8_t* ciphertext,
    size_t len,
    uint8_t* plaintext,
    const aes_ctx* ks,
    const uint8_t* iv);

/*
    Returns a Message Authentication Code (MAC) for an AES message.
    This MAC is a tag equal in size to the AES block size computed by passing the plaintext
        through the AES CBC algorithm for an IV = 0 with a unique key schedule.
        If you do use a unique key, you must be sure to exchange this second key
        with the host to be able to verify the message.
    
    # Inputs #
    <> plaintext = pointer to data to encrypt (pass through padding helper func first)
    <> len = size of data to encrypt
    <> ciphertext = pointer to buffer to write encrypted output
    <> ks = pointer to ks schedule initialized with AESLoadKey
    
    # NOTICES #
    ** DO NOT use the same key schedule for hashlib_AESOutputMAC() as you would for
        hashlib_AESEncrypt(). This exposes your message to attacks. Generate two keys,
        load them into separate key schedules, and use one for MAC and one for encryption. **
    ** It is recommended to use SCHM_ISO_M2 to pad the plaintext before passing it
        to this function. Use hashlib_PadInputPlaintext(). **
 */
bool hashlib_AESOutputMAC(
    const uint8_t* plaintext,
    size_t len,
    uint8_t* ciphertext,
    const aes_ctx* ks);

/*
    This function verifies the MAC for a given ciphertext. Use this function to verify the integrity of the message prior to Decryption
    This function expects the IPsec standard for concatenating the ciphertext and the MAC
    
    # Inputs #
    <> ciphertext = pointer to ciphertext to verify. Ciphertext should be formated [IV, encrypted_msg, MAC],
        where MAC = MAC(IV, encrypted_msg)
    <> len = size of the ciphertext to verify (should be equal to padded message + 1 block for MAC)
    <> ks_mac = the key schedule with which to verify the MAC
    * Compares the CBC encryption of the ciphertext (excluding the last block) over ks_mac with the last block of the ciphertext

 */
bool hashlib_AESVerifyMAC(const uint8_t *ciphertext, size_t len, const aes_ctx *ks_mac);

/*
    A Helper Macro to perform an AES-CBC encryption of a padded plaintext with a MAC added
    This function follows the IPsec standard for concatenation of ciphertext and MAC
    
    # Inputs #
    <> plaintext = pointer to data to encrypt
    <> len = size of data to encrypt (this is the ACTUAL size, not padded size)
    <> ciphertext = pointer to buffer to write encrypted message
    <> ks_encrypt = pointer to the key schedule to use for encryption
    <> ks_mac = pointer to the key schedule to use for the MAC  ** MUST BE DIFFERENT THAN KS_ENCRYPT **
    <> pad_schm = the padding scheme to use for encryption
    <> iv = the initialization vector (random buffer of size AES_BLOCKSIZE) to use for encryption
    
    # Outputs #
    <> A full ciphertext in ciphertext containing:
        - 1 block IV
        - N length encrypted message
        - 1-block MAC( IV, N, key_mac)
 */
#define hashlib_AESEncryptWithMAC(plaintext, len, ciphertext, ks_encrypt, ks_mac, pad_schm, iv) \
            {   \
                size_t padded_pt_size = hashlib_GetAESPaddedSize((len)); \
                uint8_t* padded_pt = hashlib_AllocContext(padded_pt_size); \
                hashlib_AESPadMessage((plaintext), padded_pt_size, padded_pt, (pad_schm)); \
                hashlib_AESEncrypt(padded_pt, padded_pt_size, (&ciphertext[AES_BLOCKSIZE]), (ks_encrypt), (iv)); \
                memcpy((ciphertext), (iv), AES_BLOCKSIZE); \
                hashlib_AESOutputMAC((ciphertext), padded_pt_size+AES_BLOCKSIZE, &ciphertext[padded_pt_size+AES_BLOCKSIZE], (ks_mac)); \
                free(padded_pt); \
            }

// ###############################
// #### BASE 64 ENCODE/DECODE ####
// ###############################
// Helper functions for bcrypt, but may be useful

/*
    Encode a byte string into a base-64 string
    
    # Inputs #
    <> b64buffer = pointer to a buffer to write base-64 output
    <> data = pointer to buffer containing data to encode
    <> len = length of data to encode
 */
bool hashlib_b64encode(char *b64buffer, const uint8_t *data, size_t len);

/*
    Decode a base-64 string
    
    # Inputs #
    <> buffer = pointer to buffer to write decoded output
    <> len = size of data to output (this is output length, not input length)
    <> b64data = pointer to buffer containing data to decode
 */
bool hashlib_b64decode(uint8_t *buffer, size_t len, const char *b64data);

#endif
