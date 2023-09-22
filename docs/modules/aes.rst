
.. _aes:

Advanced Encryption Standard
===============================

.. raw:: html

  <p style="background:rgba(176,196,222,.5); padding:10px; font-family:Arial; margin:20px 0;"><span style="font-weight:bold;">Module Functionality</span><br />Provides a fast, secure algorithm for two parties to exchange information privately using a single key for encryption and decryption. Advanced Encryption Standard is currently the gold standard for encryption and is used all over the place.</p>
  
Cipher Modes
________________

.. doxygenenum:: cryptx_aes_cipher_modes
	:project: CryptX
 
Cipher Flags
______________
	
.. doxygenenum:: cryptx_aes_padding_schemes
	:project: CryptX
 
.. doxygenenum:: cryptx_aes_default_flags
	:project: CryptX
 
.. doxygendefine:: cryptx_aes_cbc_flagset
  :project: CryptX
  
.. doxygendefine:: cryptx_aes_ctr_flagset
  :project: CryptX
  
.. doxygendefine:: cryptx_aes_gcm_flagset
  :project: CryptX
 
Macros
________

.. doxygendefine:: CRYPTX_KEYLEN_AES128
  :project: CryptX

.. doxygendefine:: CRYPTX_KEYLEN_AES192
  :project: CryptX
  
.. doxygendefine:: CRYPTX_KEYLEN_AES256
  :project: CryptX
  
.. doxygendefine:: CRYPTX_BLOCKSIZE_AES
  :project: CryptX
  
.. doxygendefine:: cryptx_aes_get_ciphertext_len
  :project: CryptX
  
Response Codes
_______________

.. doxygenenum:: aes_error_t
	:project: CryptX

Functions
____________

.. doxygenfunction:: cryptx_aes_init
	:project: CryptX
	
.. doxygenfunction:: cryptx_aes_encrypt
	:project: CryptX
	
.. doxygenfunction:: cryptx_aes_decrypt
	:project: CryptX
 
----
	
The following functions are only valid for Galois Counter Mode (GCM). Attempting to use them for any other cipher mode will return **AES_INVALID_CIPHERMODE**.

.. doxygenfunction:: cryptx_aes_update_aad
	:project: CryptX

.. doxygenfunction:: cryptx_aes_digest
	:project: CryptX

.. doxygenfunction:: cryptx_aes_verify
	:project: CryptX


Additional Notes
__________________

.. warning::

  * Cycle your AES key after encrypting 2^64 blocks of data with the same key. If you ever reach this on a freaking calculator I will literally send you some kind of metal.
  .. |br|::
  * CBC and CTR modes by themselves ensure confidentiality but do not provide any assurances of message integrity or authenticity. If you need a truly secure construction, use GCM mode or append a keyed hash (HMAC) to the encrypted message.
  .. |br|::
  * **GCM-Specific**: The context maintains flags to determine what functions are valid to call for the current state. When the context is first initialized any of the other AES functions are valid. This can be *cryptx_aes_update_aad* or *cryptx_aes_encrypt*. However, once the first call to encrypt occurs, you can no longer call update_aad. Once you call *cryptx_aes_digest* to return an authentication tag for the message, the context can no longer be used, period. This is an implementation detail meant to prevent the *GCM nonce-misuse/forbidden attack* vulnerability [CIT1]_. You will need to initialize the context (you can reuse the existing context) again with the same key but use a different IV.
  
  
  
  
.. [CIT1] https://csrc.nist.gov/csrc/media/Projects/crypto-publication-review-project/documents/initial-comments/sp800-38d-initial-public-comments-2021.pdf, Page 2
