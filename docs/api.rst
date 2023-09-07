.. _api:

API Overview
===============

You must include the library's header in any file within your project where a function from the library is used.

.. code-block:: c

	#include <cryptx.h>
   

Secure Random Number Generation
___________________________________

Randomness is essential to proper encryption. Without a secure means of generating randomness, encryption has no guarantee of being secure. We'll talk more about what this means in the section on :ref:`Encryption <l_encrypt>`. Generic random number generators, like the one provided in the CE C toolchain, are not sufficient for cryptography because they are **deterministic** (def: a single input maps to a single output). Generally these generators are seeded with insecure information such as system time. If an attacker recovers the seed the output of the generator is compromised.

Generators intended for use with cryptography need to address these shortcomings. Their output must be indistinguishable from truly random (giving an attacker negligibly better odds than that of predicting any bit of a truly random sequence). Additionally, compromise of the generator's state (i.e. seed or other state information) should not compromise the effective security of the generator. The generator provided by this library meets those constraints. For details, see the :ref:`Analysis & Overview <analysis>` page.

**Using the Secure RNG**

.. code-block:: c
  
  // cryptx_csrand_init() is now called automatically when any
  // random get or fill function is called
  
  // returning a single u_rand_int
  uint32_t rand = cryptx_csrand_get();
  
  // filling a buffer with random bytes
  #define BUFLEN  16
  uint8_t rand[BUFLEN];
  cryptx_csrand_fill(rand, BUFLEN);
  
* :ref:`view csrand documentation <csrand>`

----

Integrity Verification
________________________

An important aspect of securing information is the ability to ensure that information has not been tampered with. This tampering can occur in long-term storage (ex: a bad actor attempts to modify a file on a system) or in transit (ex: a bad actor attempts to modify the contents of an Internet packet). A secure means of communication (or storage) needs the ability to detect such tampering.

**Hashes** and **HMAC** are tools that assist with integrity verification. The standard hash produces a fixed-length value (called a *digest*) from an arbitrary-length stream of data. Because secure hashes have a negligibly low chance of collision (two different inputs producing the same output), they can detect changes to a stream of data. An HMAC works similarly, except it transforms the hash state using a key that is generally known only to authorized parties prior to hashing the data. This means that an HMAC can only be generated or validated by an authorized party. A HMAC is also sometimes referred to as a *keyed hash*.

**Using the Hash API**

.. code-block:: c

  char* text = "Hello World!"   // String to hash
  cryptx_hash_ctx hash;         // Declare hash context
  
  if(!cryptx_hash_init(&hash, SHA256))  // Initialize hash context
    return;   // exit if fails
  uint8_t digest[hash.digest_len];  // Create a buffer of correct size for hash
  
  cryptx_hash_update(&hash, text, strlen(text));  // Hash string
  cryptx_hash_digest(&hash, digest);    // Return digest
  // `digest` now contains the hash value
  
* :ref:`view hash documentation <hash>`

**Using the HMAC API**

.. code-block:: c

  char* text = "Hello World!"   // String to hash
  cryptx_hmac_ctx hash;         // Declare hmac context
  #define HMAC_KLEN 16
  uint8_t key[HMAC_KLEN];       // Define HMAC key buffer
  
  // generate random key
  cryptx_csrand_fill(key, HMAC_KLEN);
  
  // intialize HMAC for given key and algorithm
  cryptx_hmac_init(&hash, key, HMAC_KLEN, SHA256);
  uint8_t digest[hash.digest_len];  // Create a buffer of correct size for hash
  
  cryptx_hmac_update(&hash, text, strlen(text));  // Hash string
  cryptx_hmac_digest(&hash, digest);    // Return digest
  // `digest` now contains the hmac value

* :ref:`view hmac documentation <hmac>`

**Using the MGF1 API**

**MGF1** (Mask-Generation Function v1) is a hash-derived function that allows for a digest of arbitrary length to be returned from a data stream of given size. Its usage is similar to the hash API above.

.. code-block:: c

  char* text = "Hello World!"   // String to hash
  #define MGF1BUF_LEN 32
  uint8_t mgf1buf[MGF1BUF_LEN];
  
  cryptx_hash_mgf1(text, strlen(text), mgf1buf, MGF1BUF_LEN, SHA256);
  // `mgf1buf` now contains the digest value

* :ref:`view mgf1 documentation <mgf1>`

**Comparing two Digests Securely**

A cryptography library needs a safe way to compare two digests to determine if they are the same. The `memcmp` and `strcmp/strncmp` functions in the toolchain are not timing-safe; they return as soon as a mismatch is found. This causes slight variations in execution time that may reveal which character(s) of the digest are correct. This library provides a variant of this function in which the full length provided is parsed regardless of where the first mismatch is leading to no variance in execution time. Such a function is referred to as a *constant-time implementation*.

.. code-block:: c
  
  #define RECV_BUF_LEN 1024
  uint8_t buf[RECV_BUFF_LEN];
  size_t packet_len;
  
  // get incoming data into `buf`, update `packet_len`
  // assume last 32 bytes of `buf` are a hash of the rest
  network_recv(buf, &packet_len);
  
  // hash the data on receiving end
  cryptx_hash_ctx hash;
  cryptx_hash_init(&hash, SHA256);
  uint8_t t_digest[hash.digest_len];
  cryptx_hash_update(&hash, buf, packet_len-32);
  cryptx_hash_digest(&hash, t_digest);
  
  // compare computed digest with one embedded in packet
  if(!cryptx_digest_compare(t_digest, &buf[packet_len-32], hash.digest_len))
    return 1;   // data failed integrity check
    
* :ref:`view digest_compare documentation <digest_compare>`
  
**Converting a Digest to a String**

Lastly, for debugging purposes and occasionally for UI purposes it may be desired to display a digest to the user as a readable string. A function is provided by this library to convert a binary digest into its printable hex-string equivalent.

.. code-block:: c

  // assume some digest is in `digest`
  char hexstr[hash.digest_len * 2 + 1];
  cryptx_digest_tostring(digest, hash.digest_len, hexstr);
  printf("%s", hexstr);
  
* :ref:`view digest_tostring documentation <digest_tostring>`

----

Encryption & Key Exchange
__________________________

Data obfuscation is another layer of information securty which is achieved through the use of encryption, or the rendering of information indecipherable for anyone without the key used to encrypt it. Encryption can be intended to protect information in long-term storage as well as to protect information in transit between two authorized endpoints.

**AES - Symmetric Encryption**

AES (*Advanced Encryption Standard*) is currently the gold standard for secure data transmission and storage. The thing that makes AES great is that it is fast and secure. Running it on the calculator takes barely any time. However, AES does have a number of operational parameters and constraints that can make using it a bit complicated. We'll try to summarize that information as simply as possible.

* **Key-Length**
  
  AES has three operational key-lengths: 128, 192, and 256 bits. The length of the key also controls how many rounds (repetitions) of encryption occur. **Using 256 bit keys is recommended.**
  
* **Cipher Modes**
  
  CryptX supports three operational cipher modes: CBC, CTR, and GCM modes. **Using GCM is recommended as it integrates integrity verification into the output.**
  
* **Initialization Vector**
  
  AES uses an *initialization vector* (iv) which is a buffer of psuedo-random bytes specific to the session (or message for GCM mode).

.. code-block:: c
  
  // ** As Sender **
  
  char *msg = "The dog jumped over the fox!";   // string to send
  cryptx_aes_ctx aes;   // declare empty AES context
  uint8_t aes_key[CRYPTX_AES_256_KEYLEN];   // declare AES key buffer
  cryptx_csrand_fill(aes_key, CRYPTX_AES_256_KEYLEN); // random key
  uint8_t iv[CRYPTX_AES_IV_SIZE];    // declare IV
  cryptx_csrand_fill(iv, CRYPTX_AES_IV_SIZE);   // random iv
  
  if(cryptx_aes_init(&aes, aes_key, CRYPTX_AES_256_KEYLEN,
                    iv, CRYPTX_AES_IV_SIZE, CRYPTX_AES_GCM_FLAGS))
    return;   // AES initialization error
    
  size_t msg_len = strlen(msg) + 1;
  // encrypt in-place is valid
  if(cryptx_aes_encrypt(&aes, msg, msg_len, msg))
    return;   // AES encryption failed
    
  uint8_t auth_tag[CRYPTX_AES_AUTHTAG_SIZE];
  if(cryptx_aes_digest(&aes, auth_tag))
    return;   // AES digest return failed
  
  // at this point the AES context is marked invalid until initialized again with a new IV.
  // See warning below
  
  // send receiver all information necessary to authenticate and decrypt
  network_send(iv, CRYPTX_AES_IV_SIZE);
  network_send(auth_tag, CRYPTX_AES_AUTHTAG_SIZE);
  network_send(msg, msg_len);
  
.. warning::
  GCM is vulnerable to a nasty tag forgery attack if the same IV is reused for multiple message/tag pairs. Generate and set a new IV for the context after a digest is returned.

.. code-block:: c
  
  // ** As Receiver **
  
  // Assume that `aes_key` has already been exchanged
  cryptx_aes_ctx aes;   // Define empty AES context
  
  // Allocate buffer for incoming packets
  #define RECVBUF_LEN 1024
  uint8_t buf[RECVBUF_LEN];
  size_t buf_len;
  
  // Receive message to `buf` update `buf_len`
  network_recv(buf, &buf_len);
  
  // mirroring sent data above, IV is first 16 bytes of `buf`
  if(cryptx_aes_init(&aes, aes_key, CRYPTX_AES_256_KEYLEN,
                    buf, CRYPTX_AES_IV_SIZE, CRYPTX_AES_GCM_FLAGS))
    return;   // AES initialization error
  
  // these will be used multiple times
  // msg follows authtag and is rest of buf_len
  uint8_t *msg = &buf[CRYPTX_AES_IV_SIZE + CRYPTX_AES_AUTHTAG_SIZE];
  size_t msg_len = buf_len - CRYPTX_AES_IV_SIZE + CRYPTX_AES_AUTHTAG_SIZE;
    
  // authenticate incoming message first
  // authtag is 16 bytes and follows IV
  // REFUSE DECRYPTION IF INVALID
  if!(cryptx_aes_verify(&aes, NULL, 0, msg, msg_len, &buf[CRYPTX_AES_IV_SIZE]))
    return;   // return if auth fails
    
  if(cryptx_aes_decrypt(&aes, msg, msg_len, msg))
    return;   // AES decryption failed
    
  printf("%s", msg);
  


Password-Based Key Derivation
______________________________
.. _`Password-Based Key Derivation` ::
	
.. doxygenfunction:: cryptx_hmac_pbkdf2
	:project: CryptX

Symmetric Encryption
_____________________
.. _`Symmetric Encryption` ::
AES is currently regarded as the gold standard for symmetric encryption. It is the primary encryption algorithm used in a secure session, after a (usually slower) key negotiation has succeeded. AES is fast and secure (to date it has not been broken if properly implemented). If you need the best possible security with this library, use AES-GCM cipher mode.

.. doxygenstruct:: cryptx_aes_ctx
	:project: CryptX
	:members: keysize,round_keys,iv,ciphermode,op_assoc,metadata

.. note::

	Contexts are not bidirectional due to being stateful. If you need to process both encryption and decryption, initialize seperate contexts for encryption and decryption. Both contexts will use the same key, but different initialization vectors.
	
	To prevent misuse, a context locks to the first operation it is used with and will return an error if used incorrectly.
	
.. warning::

	It is recommended to cycle your key after encrypting 2^64 blocks of data with the same key.
	
	Do not manually edit the context structure. This will break the cipher configuration. If you want to change cipher modes, do so by calling *cryptx_aes_init* again.
	
	CBC and CTR modes by themselves ensure confidentiality but do not provide any assurances of message integrity or authenticity. If you need a truly secure construction, use GCM mode or append a keyed hash (HMAC) to the encrypted message..

.. doxygenenum:: cryptx_aes_cipher_modes
	:project: CryptX
	
.. doxygenenum:: cryptx_aes_padding_schemes
	:project: CryptX
	
Here are some macros to assist with defining buffers for keys of supported length.

.. doxygendefine:: CRYPTX_AES_128_KEYLEN
	:project: CryptX
.. doxygendefine:: CRYPTX_AES_192_KEYLEN
	:project: CryptX
.. doxygendefine:: CRYPTX_AES_256_KEYLEN
	:project: CryptX
	
And here are some macros defining properties of the cipher.

.. doxygendefine:: CRYPTX_AES_BLOCK_SIZE
	:project: CryptX
.. doxygendefine:: CRYPTX_AES_IV_SIZE
	:project: CryptX
.. doxygendefine:: CRYPTX_AES_AUTHTAG_SIZE
	:project: CryptX
	
Some macros for passing cipher configuration options to *cryptx_aes_init*.

.. doxygendefine:: CRYPTX_AES_CBC_FLAGS
	:project: CryptX
.. doxygendefine:: CRYPTX_AES_CTR_FLAGS
	:project: CryptX
.. doxygendefine:: CRYPTX_AES_GCM_FLAGS
	:project: CryptX

This macro returns the full size required by the ciphertext. This really only applies to CBC mode. CTR and GCM modes have the same ciphertext and plaintext length.

.. doxygendefine:: cryptx_aes_get_ciphertext_len
	:project: CryptX
	
.. doxygenenum:: aes_error_t
	:project: CryptX

.. doxygenfunction:: cryptx_aes_init
	:project: CryptX
	
.. doxygenfunction:: cryptx_aes_encrypt
	:project: CryptX
	
.. doxygenfunction:: cryptx_aes_decrypt
	:project: CryptX
	
The following functions are only valid for Galois Counter Mode (GCM). Attempting to use them for any other cipher mode will return **AES_INVALID_CIPHERMODE**.

.. doxygenfunction:: cryptx_aes_update_aad
	:project: CryptX

.. doxygenfunction:: cryptx_aes_digest
	:project: CryptX

.. doxygenfunction:: cryptx_aes_verify
	:project: CryptX

Public Key Encryption
______________________
.. _`Public Key Encryption` ::

RSA is currently one of the most commonly used key exchange/public key encryption methods. It is commonly used to share a secret for symmetric encryption (such as AES) at the start of a secure session. In recent times, however, RSA has been becoming easier to defeat due to advances in computing. This implementation is encrypt-only, supports modulus length between 1024 and 2048 bits, and uses a public exponent of :math:`2^{2^4} + 1` or 65,537.

.. doxygendefine:: CRYPTX_RSA_MODULUS_MAX
	:project: CryptX

.. doxygenenum:: rsa_error_t
	:project: CryptX
	
.. doxygenfunction:: cryptx_rsa_encrypt
	:project: CryptX
	
Key Exchange Protocols
_______________________
.. _`Key Exchange Protocols` ::

Elliptic curves are a newer introduction to cryptography and they boast more security than more traditional algorithms. For example, in order to achieve the same security level you would have with a 2048-bit RSA key, you need only around 240 bits. **Elliptic Curve Diffie-Hellman** is a variation on standard Diffie-Hellman that uses elliptic curves to transform a private key into a public key.

**Standard Diffie-Hellman**

.. math::
	&pubkey = G^{privkey} \mod m \\
	&secret = rpubkey^{privkey} \mod m \\
	&where: \\
	&G = public\_base \\
	&m = public\_modulus
	
**Elliptic Curve Diffie-Hellman**

.. math::
	&pubkey = G * privkey \\
	&secret = rpubkey * privkey * cofactor \\
	&where: \\
	&G = base\_point\_on\_curve
	
This library implements SECT233k1. This was chosen (1) because it offers approximately the same security level as RSA-2048, and (2) koblitz curves can be mathematically optimzed better than other curves. On a platform as slow as the TI-84+ CE, these optimizations are critical to make using this feasible. Even so, this elliptic curve implementation clocks in at about 14 seconds per operation (pubkey generation, secret compuation).
	
.. doxygendefine:: CRYPTX_ECDH_PRIVKEY_LEN
	:project: CryptX

.. doxygendefine:: CRYPTX_ECDH_PUBKEY_LEN
	:project: CryptX
	
.. doxygendefine:: CRYPTX_ECDH_SECRET_LEN
	:project: CryptX
	
.. doxygendefine:: cryptx_ecdh_generate_privkey
	:project: CryptX
	
.. doxygenenum:: ecdh_error_t
	:project: CryptX
	
.. doxygenfunction:: cryptx_ecdh_publickey
	:project: CryptX
	
.. doxygenfunction:: cryptx_ecdh_secret
	:project: CryptX
	
Abstract Syntax Notation One
_____________________________
.. _`Abstract Syntax Notation One` ::

Abstract Syntax Notation One (ASN.1) is a form of data encoding common to cryptography and one of the two usual output formats for keyfiles. ASN.1 is a tree structure of objects encoded by type, size, and data. A common serialization format for ASN.1 is DER, which stands for *Distinguished Encoding Rules*. It is standardized for cryptography. See the example below which expresses the encoding of a public key from *Public Key Cryptography Standards #8 (PKCS#8)*.

.. code-block:: c
	
	PublicKeyInfo ::= SEQUENCE {
		algorithm AlgorithmIdentifier :: SEQUENCE {
			algorithm id OBJECT IDENTIFIER,
			parameters ANY DEFINED BY algorithm OPTIONAL
		}
		PublicKey BIT STRING
	}

.. note::
	Do not confuse encryption with encoding. Encoding is merely a method of expressing information. It does not prevent unauthorized parties from reading or modifying the data.
	
.. doxygenenum:: CRYPTX_ASN1_TAGS
	:project: CryptX
	
.. doxygenenum:: CRYPTX_ASN1_CLASSES
	:project: CryptX
	
.. doxygenenum:: CRYPTX_ASN1_FORMS
	:project: CryptX
	
.. doxygendefine:: cryptx_asn1_get_tag
	:project: CryptX
	
.. doxygendefine:: cryptx_asn1_get_class
	:project: CryptX
	
.. doxygendefine:: cryptx_asn1_get_form
	:project: CryptX
	
.. doxygenenum:: asn1_error_t
	:project: CryptX
	
.. doxygenfunction:: cryptx_asn1_decode
	:project: CryptX
	
Base64 Encoding and Decoding
____________________________
.. _`Base64 Encoding and Decoding` ::

Base64 (sextet-encoding) is the second of two encoding formats common to cryptography, including keyfiles exported by cryptographic libraries. In fact, PEM encoding usually has the key encoded first with ASN.1 and then into base64.

In base64 a stream of octets (8 bits per byte) is parsed as a bit string in groups of six bits (hence sextet) which is then mapped to one of 64 printable characters.

.. doxygendefine:: cryptx_base64_get_encoded_len
	:project: CryptX
	
.. doxygendefine:: cryptx_base64_get_decoded_len
	:project: CryptX
	
.. doxygenfunction:: cryptx_base64_encode
	:project: CryptX
	
.. doxygenfunction:: cryptx_base64_decode
	:project: CryptX
	
Hazardous Materials
___________________

This segment contains lower-level functions that are not part of the standard API. This allows developers who know what they are doing to write their own constructions. Remember that it is generally ill-advised to try to implement your own cryptography.

.. code-block:: c

	#define CRYPTX_ENABLE_HAZMAT	// to enable the hazardous materials
	
.. doxygenfunction:: cryptx_hazmat_aes_ecb_encrypt
	:project: CryptX
	
.. doxygenfunction:: cryptx_hazmat_aes_ecb_decrypt
	:project: CryptX
	
.. doxygenfunction:: cryptx_hazmat_rsa_oaep_encode
	:project: CryptX

.. doxygenfunction:: cryptx_hazmat_rsa_oaep_decode
	:project: CryptX
	
.. doxygenfunction:: cryptx_hazmat_powmod
	:project: CryptX

.. doxygendefine:: CRYPTX_GF2_INTLEN
	:project: CryptX

.. doxygenstruct:: cryptx_ecc_point
	:project: CryptX
	
.. doxygenfunction:: cryptx_hazmat_ecc_point_add
	:project: CryptX
	
.. doxygenfunction:: cryptx_hazmat_ecc_point_double
	:project: CryptX
	
.. doxygenfunction:: cryptx_hazmat_ecc_point_mul_scalar
	:project: CryptX
