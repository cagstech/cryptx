.. _api:

API Documentation
===================

You must include the library's header in any file within your project where a function from the library is used.

.. code-block:: c

	#include <cryptx.h>
   

Secure Random Number Generation
___________________________________

.. note::

  Randomness is essential to proper encryption. Without a secure means of generating randomness, encryption has no guarantee of being secure. Generic random number generators, like the one provided in the CE C toolchain, are not sufficient for cryptography because they are **deterministic** (def: a single input maps to a single output). Generally these generators are seeded with insecure information such as system time. If an attacker recovers the seed the output of the generator is compromised.

  Generators intended for use with cryptography need to address these shortcomings. Their output must be indistinguishable from truly random (giving an attacker negligibly better odds than that of predicting any bit of a truly random sequence). Additionally, compromise of the generator's state (i.e. seed or other state information) should not compromise the effective security of the generator. The generator provided by this library meets those constraints. For details, see the :ref:`Analysis & Overview <analysis>` page.
  
.. code-block:: c
  :caption: Using the Secure RNG
  
  // cryptx_csrand_init() is now called automatically when any
  // random get or fill function is called
  
  // returning a single u_rand_int
  uint32_t rand = cryptx_csrand_get();
  
  // filling a buffer with random bytes
  #define BUFLEN  16
  uint8_t rand[BUFLEN];
  cryptx_csrand_fill(rand, BUFLEN);
  
* :ref:`view csrand function documentation <csrand>`
  

Integrity Verification
________________________

.. note::
  An important aspect of securing information is the ability to ensure that information has not been tampered with. This tampering can occur in long-term storage (ex: a bad actor attempts to modify a file on a system) or in transit (ex: a bad actor attempts to modify the contents of an Internet packet). A secure means of communication (or storage) needs the ability to detect such tampering.

  **Hashes** and **HMAC** are tools that assist with integrity verification. The standard hash produces a fixed-length value (called a *digest*) from an arbitrary-length stream of data. Because secure hashes have a negligibly low chance of collision (two different inputs producing the same output), they can detect changes to a stream of data. An HMAC works similarly, except it transforms the hash state using a key that is generally known only to authorized parties prior to hashing the data. This means that an HMAC can only be generated or validated by an authorized party. A HMAC is also sometimes referred to as a *keyed hash*.

.. code-block:: c
  :caption: Returning a hash digest

  char* text = "Hello World!"   // String to hash
  cryptx_hash_ctx hash;         // Declare hash context
  
  cryptx_hash_init(&hash, SHA256);  // Initialize hash context
  uint8_t digest[hash.digest_len];  // Buffer of digest length
  cryptx_hash_update(&hash, text, strlen(text));  // Hash string
  cryptx_hash_digest(&hash, digest);    // Return digest
  // `digest` now contains the hash value

.. code-block:: c
  :caption: Returning an HMAC digest

  char* text = "Hello World!"   // String to hash
  cryptx_hmac_ctx hash;         // Declare hmac context
  #define HMAC_KLEN 16
  uint8_t key[HMAC_KLEN];       // Define HMAC key buffer
  
  // generate random key
  cryptx_csrand_fill(key, HMAC_KLEN);
  
  // intialize HMAC for given key and algorithm
  cryptx_hmac_init(&hash, key, HMAC_KLEN, SHA256);
  
  uint8_t digest[hash.digest_len];  // Buffer of digest length
  cryptx_hash_update(&hash, text, strlen(text));  // Hash string
  cryptx_hash_digest(&hash, digest);    // Return digest
  // `digest` now contains the hmac value

* :ref:`view hash function documentation <hash>`
* :ref:`view hmac function documentation <hmac>`

There is a final method of integrity verification that will be touched upon in the :ref:`Encryption <l_encrypt_w_auth>` section.
 
.. doxygenfunction:: cryptx_digest_compare
	:project: CryptX
	
.. doxygenfunction:: cryptx_digest_tostring
	:project: CryptX

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
