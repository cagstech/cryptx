.. _ec:

Elliptic Curves
================

.. raw:: html

  <p style="background:rgba(176,196,222,.5); padding:10px; font-family:Arial; margin:20px 0;"><span style="font-weight:bold;">Module Functionality</span><br />Provides elliptic curve cryptography&mdash;generation of public/private keypairs, the diffie-hellman key exchange protocol, and digital signature algorithm.</p>

Macros
_______

.. doxygendefine:: CRYPTX_KEYLEN_EC_PRIVKEY
	:project: CryptX

.. doxygendefine:: CRYPTX_KEYLEN_EC_PUBKEY
	:project: CryptX
  
.. doxygendefine:: CRYPTX_KEYLEN_EC_SECRET
	:project: CryptX
 
Response Codes
_______________
  
.. doxygenenum:: ec_error_t
	:project: CryptX
 
Functions
___________
	
.. doxygenfunction:: cryptx_ec_keygen
	:project: CryptX
 
.. doxygenfunction:: cryptx_ec_secret
	:project: CryptX
 
.. code-block:: c

  struct _ec_keys {
    uint8_t privkey[CRYPTX_KEYLEN_EC_PRIVKEY];
    uint8_t pubkey[CRYPTX_KEYLEN_EC_PUBKEY];
  };
  
  struct _ec_keys ec_keys;
  uint8_t secret[CRYPTX_KEYLEN_EC_SECRET],
          rpubkey[CRYPTX_KEYLEN_EC_PUBKEY];
  
  if(cryptx_ec_keygen(ec_keys.privkey, ec_keys.pubkey) != EC_OK) return;
  network_send(ec_keys.pubkey, sizeof(ec_keys.pubkey));
  
  // await remote public key
  network_recv(rpubkey, NULL);
  
  if(cryptx_ec_secret(ec_keys.privkey, rpubkey, secret) != EC_OK) return;
  // secret should now be the same for both parties
  
