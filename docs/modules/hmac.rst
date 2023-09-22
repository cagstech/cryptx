.. _hmac:

Hash-Based MAC
===============

.. raw:: html

  <p style="background:rgba(176,196,222,.5); padding:10px; font-family:Arial; margin:20px 0;"><span style="font-weight:bold;">Module Functionality</span><br />Provides hashed-based message authentication code (HMAC) functionality. HMAC is essentially a hash with its state transformed using a key before and after the data is hashed. Standard hashes verify that data has not changed. HMAC also ensures that only an entity with the key can sign and verify the message.</p>
  
Enumerations
_____________

.. doxygenenum:: cryptx_hash_algorithms
  :project: CryptX
  
Macros
________

.. doxygendefine:: CRYPTX_DIGESTLEN_SHA1
	:project: CryptX
 
.. doxygendefine:: CRYPTX_DIGESTLEN_SHA256
	:project: CryptX
  
Functions
_____________
  
.. doxygenfunction:: cryptx_hmac_init
	:project: CryptX
	
.. doxygenfunction:: cryptx_hmac_update
	:project: CryptX
	
.. doxygenfunction:: cryptx_hmac_digest
	:project: CryptX
 
.. code-block:: c
  
  char *msg = "Hash this string";
  crytx_hmac_ctx h;
  #define HMAC_KLEN 16
  uint8_t hmac_key[HMAC_KLEN];
  cryptx_csrand_fill(hmac_key, HMAC_KLEN);
  
  // initialize hash
  cryptx_hmac_init(&h, hmac_key, HMAC_KEN, SHA256);
  
  // allocate buffer for digest
  uint8_t digest[h.digest_len];
  
  // hash the string
  cryptx_hmac_update(&h, msg, strlen(msg));
  
  // return the digest
  cryptx_hmac_digest(&h, digest);
  
----

.. _pbkdf2:

Password-Based Key Derivation
_____________________________

**Password-Based Key Derivation Function Two (PBKDF2)** is a function that uses an HMAC algorithm to generate a key from a password. This is normally used to generate encryption keys. You can also probably get away with using to encrypt passwords for storage on your calculator. It's certainly not the most secure password hashing algorithm, but for most on-calculator uses, it's probably fine.

.. doxygenfunction:: cryptx_hmac_pbkdf2
	:project: CryptX

.. code-block:: c

  // user inputs a password
  char *passwd = io_GetUserInput();
  
  // define salt of length equal to SHA256 digest for max security
  uint8_t salt[SHA256_DIGESTLEN];
  cryptx_csrand_fill(salt, SHA256_DIGESTLEN);
  
  uint8_t hpasswd[SHA256_DIGESTLEN];
  
  // hash the password using pbkdf2_hmac
  cryptx_hmac_pbkdf2(passwd, strlen(passwd),
                    salt, SHA256_DIGESTLEN,
                    hpasswd, SHA256_DIGESTLEN,
                    SHA256);
                    
  // the contents of `hpasswd` can be used as an encryption key for AES
  // or can be dumped along with `salt` as an encrypted password
  
.. note::

  For maximum security/entropy your salt should be the same length as the digest of the hash algorithm selected. This isn't enforced; you can use a smaller salt if you don't care but be aware that the absolute minimum recommended is 16 bytes/128 bits. This is a NIST [#f1]_ recommendation.

----

**Notes**

  (1) After initialization the hmac context holds the digest length for the selected algorithm. You can read it by accessing :code:`context.digest_len`. **This is the only reason you should be accessing a member of the hmac context.**
  (2) This API uses 516 bytes of *fastMem* starting at :code:`0xE30800` for scratch memory. Do not use it for anything else if you are using this module.
  
----
  
.. [#f1] `National Institute of Standards and Technology <https://www.nist.gov/>`_
