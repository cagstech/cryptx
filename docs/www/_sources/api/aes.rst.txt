
.. _aes:
.. |br| raw:: html

    <br />


function documentation: AES
===============================

.. note::

	AES contexts are directional and stateful. If you need to process both encryption and decryption, initialize seperate contexts for encryption and decryption. Both contexts will use the same key, but different initialization vectors.
	
	To prevent misuse, a context locks to the first operation it is used with and will return an error if used incorrectly.

Here are some enumerations defining cipher modes and padding schemes for CBC mode.

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
	
This enum defines possible response codes from calls to the AES API.
 
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


Additional Notes
__________________

.. warning::

  * Cycle your AES key after encrypting 2^64 blocks of data with the same key. If you ever reach this on a freaking calculator I will literally send you some kind of metal.
  .. |br|::
  * CBC and CTR modes by themselves ensure confidentiality but do not provide any assurances of message integrity or authenticity. If you need a truly secure construction, use GCM mode or append a keyed hash (HMAC) to the encrypted message.
  .. |br|::
  * **GCM-Specific**: The context maintains flags to determine what functions are valid to call for the current state. When the context is first initialized any of the other AES functions are valid. This can be *cryptx_aes_update_aad* or *cryptx_aes_encrypt*. However, once the first call to encrypt occurs, you can no longer call update_aad. Once you call *cryptx_aes_digest* to return an authentication tag for the message, the context can no longer be used, period. This is an implementation detail meant to prevent the *GCM nonce-misuse/forbidden attack* vulnerability [CIT1]_. You will need to initialize the context (you can reuse the existing context) again with the same key but use a different IV.
  
  
  
  
.. [CIT1] https://csrc.nist.gov/csrc/media/Projects/crypto-publication-review-project/documents/initial-comments/sp800-38d-initial-public-comments-2021.pdf, Page 2
