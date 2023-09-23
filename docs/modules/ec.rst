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
