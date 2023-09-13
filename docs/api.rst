.. _api:

This document is meant to serve as both an overview of the library API (through extensively-commented code samples) and an appreviated crash course on cryptography. This is so that users gain an understanding of why and how they would use the library's modules properly instead of just copypasta'ing code. Usage of this library is more likely to be done properly if users know why things are done certain ways.

Links to detailed function documentation for each module are available at end of each section of this page.

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

Key Derivation & Management
____________________________

Encryption (and HMAC) require secure key generation and management. As mentioned before the strength of your encryption system depends on the security of your keys. This includes not only that the key be generated using a secure random generator or other secure algorithm but also that the user have a means for protecting any keys that need to be persistently stored (such as for database or file encryption).

CryptX supports two methods of key generation: random and password-derived. To generate a random key, simply use the secure random generator as documented above, namely *cryptx_csrand_fill*. For a password-derived key there is an implementation of *hmac_pbkdf2* in CryptX. You would use it like so:

.. code-block:: c
  
  // `prompt_user` is a psuedo-function implying a text-input UI
  char* passwd = prompt_user();
  
  // declare buffer for AES key
  uint8_t aes_key[CRYPTX_AES_256_KEYLEN];
  
  // declare buffer for PBKDF2 salt (random bytes)
  uint8_t pbkdf2_salt[16];    // min length recommended
  cryptx_csrand_fill(pbkdf2_salt, 16);
  
  #define PBKDF2_COST   1000
  cryptx_hmac_pbkdf2(passwd, strlen(passwd),  // password and length of password
                      pbkdf2_salt, 16,        // salt and length of salt
                      aes_key, CRYPTX_AES_256_KEYLEN, // key outbuf and length of key to gen
                      PBKDF2_COST, SHA256);   // # times to iterate hash and hash alg to use
  
  // aes_key now contains a password-derived secure key
  // dump salt somewhere and require user input password to decrypt whatever
  // this key is encrypting. Note that if user forgets password, data is
  // not recoverable.
  
No matter how much people on the Internet like to claim that tech giants have your passwords and data, information security standards (like PCI-DSS, GDPR, and others) mandate that public-facing secure services--especially those that store sensitive personal information--implement these cryptosystems and store credentials using non-reversible algorithms (such as a hash) that save enough information to verify a credential but not enough to reveal it. This means that unless you are able to supply your password to generate a key for decryption, your data is VERY hard to recover. That is the nature of encryption, and it all cascades to a simple, unalienable fact that your information--be it your passwords, security keys, or other manner of security--is your responsibility. Remember that the next time you want to yell at a technican because you forgot your password.
  

----

Symmetric Encryption
_____________________

Data obfuscation is another layer of information securty which is achieved through the use of encryption, or the rendering of information indecipherable for anyone without the key used to encrypt it. Encryption can be intended to protect information in long-term storage as well as to protect information in transit between two authorized endpoints.

**AES (Advanced Encryption Standard)**

AES is currently the gold standard for secure data transmission and storage. The thing that makes AES great is that it is fast and secure. Running it on the calculator takes barely any time. However, AES does have a number of operational parameters and constraints that can make using it a bit complicated. We'll try to summarize that information as simply as possible.

* AES has three variants defined by key length:
  
  - AES-128 (128 bit keys, 10 rounds (repetitions) of encryption)
  - AES-192 (192 bit keys, 12 rounds of encryption)
  - AES-256 (256 bit keys, 14 rounds of encryption)
  - **Using 256 bit keys is recommended.**
  
* CryptX supports three operational cipher modes:
  
  - Cyclic Block Chaining (CBC)
  - Counter (CTR)
  - Galois Counter (GCM)
  - **Using GCM is recommended as it integrates integrity verification into the output.**
  
* AES uses an *initialization vector* (IV) which is a 16-byte buffer of random bytes specific to the session (or message for GCM mode) used to give the encryption randomized output.

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
  
* :ref:`view AES documentation <aes>`

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

* :ref:`view AES documentation <aes>`

Public Key Cryptography & Key Exchange Protocols
___________________________________________________

AES is great but has a major shortcoming. You need a way to agree upon the secret on both sides of the secure session prior to starting to encrypt messages using it. If you send the key in the clear (unencrypted), what's the point of the encryption then? This is where **key exchange protocols** enter the discussion. These are algorithms, some encryption methods and some mathematical computations, that allow two endpoints to agree on a shared secret for symmetric encryption without leaking the secret.

**Rivest-Shamir-Adleman (RSA) Encryption**

The first option supported within CryptX is also one of the most commonly used on the Internet today. It is an encryption system developed by computer scientists Ron Rivest and Adi Shamir and mathematician Leonard Adleman--and named for them as well. RSA is a form of *asymmetric encryption* (encryption system that uses two opposing keys, a public one to encrypt and a private one to decrypt). Because the public key is used for encryption RSA is also a form of *public key cryptography*.

How does that benefit us? Imagine you, using your web browser, attempt to connect to some secure website. Upon attempt to connect, the website sends you a public key that you can use to encrypt messages for it. You encrypt an AES secret using this public key and ship it to the website. The website decrypts that with its own private key. You and the website now have the AES secret and it was not leaked in transit (assuming the developer did things right). Go-go-gadget AES.

Using RSA on calculator with CryptX is quite simple--it just takes some time. Most key exchange protocols use hefty mathematics and the calculator takes a lot more than a few milliseconds to pull them off. 2048-bit RSA takes about 8 seconds to complete. Additionally, this implementation automatically applies the *Optimal Asymmetric Encryption Padding (OAEP) v2.2* encoding scheme. This extends the length of the message to one bit less than the length of the public modulus and incorporates randomness into the encryption.

.. code-block:: c

  #define RECVBUF_LEN 1024
  uint8_t recv_buf[RECVBUF_LEN];
  size_t recv_len;
  
  // read incoming to `recv_buf` update `recv_len`
  network_recv(recv_buf, &recv_len);
  uint8_t *rsa_pubkey = recv_buf;
  
  // define a buffer large enough to hold ciphertext
  // an encoded, RSA-encrypted message is the same length as the public modulus
  uint8_t rsa_ciphertext[recv_len];
  
  // generate AES secret
  uint8_t aes_key[CRYPTX_AES_256_KEYLEN];
  cryptx_csrand_fill(aes_key, CRYPTX_AES_256_KEYLEN);
  
  if(cryptx_rsa_encrypt(aes_key, CRYPTX_AES_256_KEYLEN,
                        rsa_pubkey, recv_len,
                        rsa_ciphertext, SHA256))
    return;   // some RSA error occurred

* :ref:`view RSA documentation <RSA>`

**Elliptic Curve Diffie-Hellman (ECDH) Key Exchange**

The second option supported within CryptX is perhaps not as widely used (and fairly new) but arguably more secure. It is an encryption system based upon the less secure Diffie-Hellman key exchange protocol, but using elliptic curve arithmetic instead of standard modular arithmetic. The behavior of an elliptic curve over a Galois field lends to a cryptosystem that is much harder to crack.

Just like with RSA, using this on the calculator is quite simple--but time-consuming. Each function--key generation and secret computation--takes about 12-14 seconds to complete.

.. code-block:: c

  uint8_t ec_privkey[CRYPTX_ECDH_PRIVKEY_LEN];
  uint8_t ec_pubkey[CRYPTX_ECDH_PUBKEY_LEN];
  uint8_t ec_secret[CRYPTX_ECDH_SECRET_LEN];
  
  // generates a random private key and associated public key
  // supports SECT233k1 elliptic curve
  // these keys are compatible with both ECDH and later ECDSA
  cryptx_ec_keygen(ec_privkey, ec_pubkey);
  
  // send your private key to the remote host
  network_send(ec_pubkey, CRYPTX_ECDH_PUBKEY_LEN);
  
  // get remote host's public key into `ec_pubkey`. Size known.
  network_recv(ec_pubkey, NULL);
  
  // compute secret
  cryptx_ecdh_secret(ec_privkey, ec_pubkey, ec_secret);
  
  // ECDH computations have the property that given:
  // keypairs: prA, puA and prB, puB, consisting of:
  // private keys: prA, prB and
  // public keys: puA, puB it follows that:
  // prA * puB == prB * puA.
  // This allows both parties to compute the same shared secret that is secure so
  // long as the private keys are not leaked.
  
  // it is advised to HASH `ec_secret` and not use it as it.

* :ref:`view elliptic curve documentation <ec>`


Cryptographic Encoding Formats
_______________________________

The *Public Key Cryptography Standards (PKCS)* defines, if you can believe it, standards for the encoding of public keys in storage and transit. The two most commonly used encoding formats are *Abstract Syntax Notation One (ASN.1)* and *Base64*. Do not confuse encryption with encoding. Encoding is merely a method of expressing information in plain-text format. It does not prevent unauthorized parties from reading or modifying the data.

**Abstract Syntax Notation One (ASN.1)**

Many cryptographic structures are encoded using *Distinguished Encoding Rules (DER)* which is a serialization format of ASN.1 standardized for cryptography. See the example below which expresses the encoding of a public key from *Public Key Cryptography Standards #8 (PKCS#8)*.

.. code-block:: c
	
	PublicKeyInfo ::= SEQUENCE {
		algorithm AlgorithmIdentifier :: SEQUENCE {
			algorithm id OBJECT IDENTIFIER,
			parameters ANY DEFINED BY algorithm OPTIONAL
		}
		PublicKey BIT STRING
	}
 
.. code-block:: c

  #define RECVBUF_LEN 1024
  uint8_t recv_buf[RECVBUF_LEN];
  size_t recv_len;
  
  // read incoming to `recv_buf` update `recv_len`
  network_recv(recv_buf, &recv_len);
  uint8_t *rsa_pubkey = recv_buf;
  
  // ** Decode DER-encoded structure **
  // decode parent SEQUENCE, tag_data and tag_datalen are pointers to data
  uint8_t *tag_data;
  size_t tag_datalen;
  if(cryptx_asn1_decode(recv_buf, recv_len, 0, NULL, &tag_datalen, &tag_data))
    return;   // decoding error, do something to handle
    
  // `PublicKey` object is actually a BIT STRING-encoded DER structure
  uint8_t *keydata;
  size_t keylen;
  if(cryptx_asn1_decode(tag_data, tag_datalen, 1, NULL, &keylen, &keydata))
    return;   // decoding error, do something to handle
    
  // Decode PKCS#1 Public Key structure
  uint8_t *keystruct;
  size_t keystruct_len;
  if(cryptx_asn1_decode(keydata, keylen, 0, NULL, &keystruct_len, &keystruct))
    return;   // decoding error, do something to handle
    
  // `keyinner` now contains two ASN.1 encoded objects, the modulus and the exponent
  uint8_t *key_modulus;
  size_t key_modulus_size;
  if(cryptx_asn1_decode(keystruct, keystruct_len, 0, NULL, &key_modulus_size, &key_modulus))
    return;   // decoding error, do something to handle
    
  // We only need modulus, library exponent is hardcoded to 65537.
  // In theory can you can *validate* that the exponent is supported
	
* :ref:`view ASN.1 documentation <encoding>`
	
**Base64 Encoding and Decoding**

Base64 (sextet-encoding) is the second of two encoding formats common to cryptography, including keyfiles exported by cryptographic libraries. In fact, PEM-encoding usually has the key encoded first with ASN.1 and then into base64. In base64 a stream of octets (8 bits per byte) is parsed as a bit string in groups of six bits (hence sextet) which is then mapped to one of 64 printable characters.

.. code-block:: c

  #define RECVBUF_LEN 1024
  uint8_t recv_buf[RECVBUF_LEN];
  size_t recv_len;
  
  // read incoming to `recv_buf` update `recv_len`
  network_recv(recv_buf, &recv_len);
  uint8_t *rsa_pubkey = recv_buf;
  
  // ** Decode PEM Base64 encoding **
  size_t octet_len = cryptx_base64_get_decoded_len(recv_len);
  uint8_t octet_data[octet_len];
  cryptx_base64_decode(octet_data, recv_buf, recv_len);
  // If this is PEM, now you have a DER-encoded object.
  // It's ASN.1 time, boi
  
* :ref:`view Base64 documentation <encoding>`

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
