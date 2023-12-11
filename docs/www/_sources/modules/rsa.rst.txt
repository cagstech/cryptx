.. _rsa:

RSA
====

.. raw:: html

  <p style="background:rgba(128,128,128,.25); padding:10px; font-family:Arial; font-size:14px;"><span style="font-weight:bold;">#cryptxdevquotes:</span> <span style="font-style:italic;">That&apos;s not how RSA works, you idiot.&emsp;- MateoConLechuga</span></p>
  <p style="background:rgba(176,196,222,.5); padding:10px; font-family:Arial; margin:20px 0;"><span style="font-weight:bold;">Module Functionality</span><br />Provides an encryption-only implemention of the Rivest-Shamir Adleman (RSA) public key encrytion system. RSA is still widely used at the start of an encrypted connection to negotiate a secret for a faster encryption algorithm like AES.</p>
  
Macros
_________

.. doxygendefine:: CRYPTX_RSA_MODULUS_MAX
	:project: CryptX
 
Response Codes
_______________

.. doxygenenum:: rsa_error_t
	:project: CryptX

Functions
____________

.. doxygenfunction:: cryptx_rsa_encrypt
	:project: CryptX
 
.. code-block:: c

  // client awaits RSA key from server
  uint8_t rsa_pubkey[CRYPTX_RSA_MODULUS_MAX];
  size_t rsa_len;
  network_recv(rsa_pubkey, &rsa_len);
  uint8_t rsa_ciphertext[rsa_len];
  
  // use RSA for secret encryption
  uint8_t aes_key[CRYPTX_KEYLEN_AES256];
  if(!cryptx_csrand_fill(aes_key, sizeof(aes_key)))) return;
  
  if(cryptx_rsa_encrypt(aes_key, CRYPTX_KEYLEN_AES256,
                        rsa_pubkey, rsa_len,
                        rsa_ciphertext, SHA256) != AES_OK)
    return;
    
  network_send(rsa_ciphertext, rsa_len);

Notes
______

(1) This implementation automatically applies Optimal Asymmetric Encryption Padding (OAEP) v2.2 encoding to the message. The length of the plaintext message to encrypt cannot exceed :code:`len(public_modulus) - (2 * chosen_hash_digestlen) - 2`.

(2) The length of the ciphertext returned is the same length as the public modulus used for encryption. This means you can allocate/reserve a buffer of that size, or just use the macro defined above for the maximum length.
