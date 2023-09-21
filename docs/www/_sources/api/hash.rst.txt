.. _hash:

Secure Hashing
===============

.. raw:: html

  <p style="background:rgba(176,196,222,.5); padding:10px; font-family:Arial; margin:20px 0;"><span style="font-weight:bold;">Module Functionality</span><br />Provides secure hashing functionality. Hashes are non-reversible cryptographic algorithms that take a stream of bytes as input and return a bytearray of fixed length called a digest. Hashes are also deterministic &mdash; a single input maps to a single output &mdash; meaning that if the input changes, even slightly, the digest also changes. A hash can detect if the content of something &mdash; like a file or an Internet packet &mdash; changes and reveal tampering if the change was not authorized.</p>
  
  
Enumerations
_______________

.. doxygenenum:: cryptx_hash_algorithms
	:project: CryptX
 
Functions
_______________

.. doxygenfunction:: cryptx_hash_init
	:project: CryptX
	
.. doxygenfunction:: cryptx_hash_update
	:project: CryptX
	
.. doxygenfunction:: cryptx_hash_digest
	:project: CryptX
 
.. code-block:: c
  
  char *msg = "Hash this string";
  crytx_hash_ctx h;
  
  // initialize hash
  cryptx_hash_init(&h, SHA256);
  
  // allocate buffer for digest
  uint8_t digest[h.digest_len];
  
  // hash the string
  cryptx_hash_update(&h, msg, strlen(msg));
  
  // return the digest
  cryptx_hash_digest(&h, digest);

----

**Mask Generation Function One (MGF1)** is a hash function that can return a digest of a variable given length. It is generally not used standalone but is a mask-generating algorithm used within the RSA module. Nonetheless, if you have need of it, feel free to use it.

.. doxygenfunction:: cryptx_hash_mgf1
	:project: CryptX
 
.. code-block:: c

  char *msg = "Hash this string";
  #define MASK_LEN  48
  uint8_t mask_buf[MASK_LEN];
  
  cryptx_hash_mgf1(msg, strlen(msg), mask_buf, MASK_LEN, SHA256);
  
.. warning::

  Do not use this function to derive a mask for a key from a password. Use **cryptx_hmac_pbkdf2** for this instead. See the :ref:`HMAC module <hmac>`.
  
----

**Notes**

  (1) After initialization the hash context holds the digest length for the selected algorithm. You can read it by accessing :code:`context.digest_len`. **This is the only reason you should be accessing a member of the hash context.**
  (2) This API uses 516 bytes of *fastMem* starting at :code:`0xE30800` for scratch memory. Do not use it for anything else if you are using this API.
