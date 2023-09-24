
.. _aes:

Advanced Encryption Standard
===============================

.. raw:: html

  <p style="background:rgba(176,196,222,.5); padding:10px; font-family:Arial; margin:20px 0;"><span style="font-weight:bold;">Module Functionality</span><br />Provides a fast, secure algorithm for two parties to exchange information privately using a single key for encryption and decryption. Advanced Encryption Standard is currently the gold standard for encryption and is one of the most widely-used encryption algorithms.</p>
  
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
 
.. code-block:: c

  cryptx_aes_ctx aes;
  char* msg = "The fox jumped over the dog!";
  uint8_t aes_key[CRYPTX_KEYLEN_AES256],
          aes_iv[CRYPTX_BLOCKSIZE_AES];
          
  // generate random key
  if(!cryptx_csrand_fill(aes_key, sizeof(aes_key))) return;
  // generate random iv
  if(!cryptx_csrand_fill(aes_iv, sizeof(aes_iv))) return;
  
  if(cryptx_aes_init(&aes, aes_key, sizeof(aes_key),
                  aes_iv, sizeof(aes_iv),
                  CRYPTX_AES_GCM, CRYPTX_AES_GCM_DEFAULTS) != AES_OK)
    return;
    
  size_t encr_len = strlen(msg)+1
  cryptx_aes_encrypt(&aes, msg, encr_len, msg);
  
  network_send(aes_iv, CRYPTX_BLOCKSIZE_AES);
  network_send(msg, encr_len);

----
	
The following functions are only valid for Galois Counter Mode (GCM). Attempting to use them for any other cipher mode will return **AES_INVALID_CIPHERMODE**.

.. doxygenfunction:: cryptx_aes_update_aad
	:project: CryptX

.. doxygenfunction:: cryptx_aes_digest
	:project: CryptX

.. doxygenfunction:: cryptx_aes_verify
	:project: CryptX
 
.. code-block:: c

  cryptx_aes_ctx aes;
  char* msg = "The fox jumped over the dog!";
  char* header = "A header string.";
  uint8_t aes_key[CRYPTX_KEYLEN_AES256],
          aes_iv[CRYPTX_BLOCKSIZE_AES],
          auth_tag[CRYPTX_BLOCKSIZE_AES];
          
  // generate random key
  if(!cryptx_csrand_fill(aes_key, sizeof(aes_key))) return;
  // generate random iv
  if(!cryptx_csrand_fill(aes_iv, sizeof(aes_iv))) return;
  
  if(cryptx_aes_init(&aes, aes_key, sizeof(aes_key),
                  aes_iv, sizeof(aes_iv),
                  CRYPTX_AES_GCM, CRYPTX_AES_GCM_DEFAULTS) != AES_OK)
    return;
    
  size_t encr_len = strlen(msg)+1
  cryptx_aes_update_aad(&aes, header, strlen(header));
  cryptx_aes_encrypt(&aes, msg, encr_len, msg);
  cryptx_aes_digest(&aes, auth_tag);
  
  network_send(aes_iv, CRYPTX_BLOCKSIZE_AES);
  network_send(msg, encr_len);
  network_send(auth_tag, CRYPTX_BLOCKSIZE_AES);

There are also some enforced constraints on when these functions can be called, intended to prevent undefined behavior as well as to close a particularly nasty tag-forgery vulnerability [#f1]_ in GCM.

+----------------------------------------------------------------------------------------+
|                          GCM FUNCTION VALIDITY CONTROL FLOW                            |
+-----------------------+-----------------------+--------------------+-------------------+
| After Function Call   | cryptx_aes_update_aad | cryptx_aes_encrypt | cryptx_aes_digest |
+=======================+=======================+====================+===================+
| cryptx_aes_init       | VALID                 | VALID              | VALID             |
+-----------------------+-----------------------+--------------------+-------------------+
| cryptx_aes_update_aad | VALID                 | VALID              | VALID             |
+-----------------------+-----------------------+--------------------+-------------------+
| cryptx_aes_encrypt    | INVALID               | VALID              | VALID             |
+-----------------------+-----------------------+--------------------+-------------------+
| cryptx_aes_digest     | INVALID               | INVALID            | INVALID           |
+-----------------------+-----------------------+--------------------+-------------------+

.. _aes_iv_req:

Initialization Vector Requirements
______________________________________

- **CBC Mode**
 
  | **Requirement**: Initialization vector must be securely-random.
  | **Non-Compliance Effect**: Vulnerability to chosen plaintext attack [#f2]_.
  | **Assurance**: Generate a random IV with :code:`cryptx_csrand_fill` for use with this mode.
  
- **CTR & GCM Modes**

  | **Requirement**: Initialization vector must be unique (not re-used) over the same key.
  | **Non-Compliance Effect**: Vulnerability to many-time pad [#f3]_.
  | **Additional Options**: A fixed nonce may preceed the counter portion of the IV. This should be securely random. Default configuration for CTR mode is an 8 byte nonce followed by an 8 byte counter, though this can be configured during cipher initialization.
  | **Assurance**: For counter block of length *N* bits, after processing :code:`2 ^ N` blocks of plaintext data: (1) generate new nonce/counter blocks and prepend to ciphertext, or (2) generate and negotiate new key.


Notes
_______

(1) The initialization vector used for the cipher state (or message for GCM mode) may be communicated to the other party as the first block of the ciphertext.

(2) The AES cipher begins to leak information after a certain number of blocks have been encrypted under a single key. This number differs by cipher mode but can range anywhere from :code:`2 ^ 48` to :code:`2^64` blocks of data. This is a stupidly large amount of data that you will never realistically reach.

(3) CBC and CTR modes by themselves ensure confidentiality but do not provide any assurances of message integrity or authenticity. If you need a truly secure construction, use GCM mode or append a keyed hash (HMAC) to the encrypted message.
  
----
  
.. [#f1] **GCM Nonce-Misuse/Forbidden Attack Vulnerability**. It involves the leaking of bits of the hash subkey used to generate the authentication tag if the same initialization vector is used to authenticate multiple messages. This allows an attacker to embed a valid signature for an altered message. To resolve this vulnerability within this GCM implementation call :code:`cryptx_aes_init` again with a new initialization vector after you return a digest for a data stream. For more details on this vulnerability `click here <https://csrc.nist.gov/csrc/media/Projects/crypto-publication-review-project/documents/initial-comments/sp800-38d-initial-public-comments-2021.pdf>`_.

.. [#f2] **Chosen Plaintext Attack**. An attack against a cryptosystem involving requesting multiple encryptions while controlling bits of the input plaintext. This allows an attacker to reveal bits of the encryption secret. To resolve this vulnerability the output of an encryption algorithm needs to be securely random. See :ref:`aes_iv_req`.

.. [#f3] **Many-Time Pad**. This vulnerability derived from the **One-Time Pad** algorithm which was one of the first encryption algorithms developed. It involved XOR'ing a message with a key of equal length and had perfect secrecy. Issues arose with this algorithm if the key began to repeat, which would reveal the plaintext given only a few ciphertexts. AES CTR and GCM modes use the counter block within the IV to generate a one-time pad and therefore are subject to this vulnerability. To resolve this vulnerability ensure that you do not allow your counter/nonce block combination to repeat under the same key.
