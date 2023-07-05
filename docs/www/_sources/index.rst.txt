Cryptography for the CE
==================================

**CryptX** is a specialty library designed for integration with the TI-84+ CE toolchain that allows developers to easily implement cryptography into their projects without needing to worry about low-level implementation details. It also allows for bugfixes, feature additions, and changes to be pushed to the library usually without requiring developers to rebuild their projects.

If this is your first introduction to the CE Toolchain, check out the `toolchain repository <https://github.com/CE-Programming/toolchain>`_ and familiarize yourself with how it works.

You may be asking yourself "What makes CryptX any different than the many other tools on various forums claiming to hide or encrypt programs?". In most cases those tools do not perform actual encryption but merely set a flag preventing the average person from seeing the programs. This does not prevent viewing, or even modification, of the data comprising those programs. This utility provides **actual** encryption. The following is an exhaustive list of what CryptX provides.

	- Hashing (Hash, HMAC, MGF1)
	- Password-Based Key Derivation
	- Secure Random Number Generation
	- Advanced Encryption Standard
	- Rivest-Shamir Adleman (RSA)
	- Elliptic Curve Diffie-Hellman (implements SECT233k1)
	- Abstract Syntax Notation One (ASN.1) and Base64 decoding
	- Timing-safe buffer comparison
	
Need more convincing? Check out the :ref:`analysis` for more technical implementation details including platform-specific security considerations.

Most of this library's modules have been tested for compatibility with several other cryptographic libraries including *openssl*, *cryptodome/pycryptodome*, and *cryptography*, although in some cases where libraries do not expose their primitives, use of their *hazardous materials* layer may be required. If you do find an incompatibility with another cryptographic library, please open an issue on the `CryptX Github <https://github.com/acagliano/cryptx>`_.


Additional Resources
---------------------
.. toctree::
    :maxdepth: 1

    static/analysis
    
    
API Documentation
----------------------

.. code-block:: c

	#include <cryptx.h>

Hashing
_________
A *hash* is a cryptographic primitive that is used to determine if data has changed in storage or in transit.

.. doxygenstruct:: cryptx_hash_ctx
	:project: CryptX
	:members: init,update,digest,digest_len,metadata
	
.. doxygenenum:: cryptx_hash_algorithms
	:project: CryptX

.. doxygenfunction:: cryptx_hash_init
	:project: CryptX
	
.. doxygenfunction:: cryptx_hash_update
	:project: CryptX
	
.. doxygenfunction:: cryptx_hash_digest
	:project: CryptX
	
.. doxygenfunction:: cryptx_hash_mgf1
	:project: CryptX

Hash-Based Message Authentication Code (HMAC)
_____________________________________________
An *HMAC* is a form of hash in which the initial state is transformed based on some application secret or random oracle known only to authorized parties. This allows for not only the integrity but also the authenticity of the information to be confirmed.

.. doxygenstruct:: cryptx_hmac_ctx
	:project: CryptX
	:members: init,update,digest,digest_len,metadata
	
.. doxygenfunction:: cryptx_hmac_init
	:project: CryptX
	
.. doxygenfunction:: cryptx_hmac_update
	:project: CryptX
	
.. doxygenfunction:: cryptx_hmac_digest
	:project: CryptX

Deriving Key from Password
___________________________
	
.. doxygenfunction:: cryptx_hmac_pbkdf2
	:project: CryptX
	
Working with Digests
_____________________

The library provides two functions for interacting with digests returned by the hash and HMAC API, and even later the tags produced by encryption.

.. doxygenfunction:: cryptx_digest_compare
	:project: CryptX
	
.. doxygenfunction:: cryptx_digest_tostring
	:project: CryptX

Secure Random Number Generation
_______________________________
This random number generator is a hardware RNG. It works by reading repeatedly in XOR mode to an entropy pool from unmapped portions of SRAM until sufficient entropy is attained to return a random number. The input is passed through a cryptographic hash to ensure maximum distribution of entropy throughout the output.
    
.. doxygenfunction:: cryptx_csrand_init
	:project: CryptX
	
.. doxygenfunction:: cryptx_csrand_get
	:project: CryptX
	
.. doxygenfunction:: cryptx_csrand_fill
	:project: CryptX

Advanced Encryption Standard (AES)
__________________________________
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

Rivest-Shamir-Adleman (RSA)
___________________________

RSA is currently one of the most commonly used key exchange/public key encryption methods. It is commonly used to share a secret for symmetric encryption (such as AES) at the start of a secure session. In recent times, however, RSA has been becoming easier to defeat due to advances in computing. This implementation is encrypt-only, supports modulus length between 1024 and 2048 bits, and uses a public exponent of :math:`2^{2^4} + 1` or 65,537.

.. doxygendefine:: CRYPTX_RSA_MODULUS_MAX
	:project: CryptX

.. doxygenenum:: rsa_error_t
	:project: CryptX
	
.. doxygenfunction:: cryptx_rsa_encrypt
	:project: CryptX
	
Elliptic Curve Diffie-Hellman
_____________________________

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
	
Base64
________

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

This segment contains lower-level functions that are not part of the standard API. This allows developers who know what they are doing to write their own constructions.

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
