.. _pkcs8:

PKCS#8
=========

.. raw:: html

  <p style="color:red; font-weight:bold; font-size:120%;">Module under development. Check back for updates.</p><p style="background:rgba(176,196,222,.5); padding:10px; font-family:Arial; margin:20px 0;"><span style="font-weight:bold;">Module Functionality</span><br />Provides functions for the import of PKCS#8-encoded public and private keys that can be used with the RSA and EC modules of this library.</p>

PKCS stands for **Public Key Cryptography Standards** and specification #8 provides general key encoding guidelines for various forms of public and private keys. Because the API of this library tends to work on raw data (rather than on key structures like other libraries do), this module provides a way to deserialize PKCS#8 keyfiles such that you can access components of the key. You can also pass these public and private key structures directly to the TLS implementation (coming soon).

PKCS#8 typically encodes keydata using the following workflow:

(1) The components of the key are encoding using ASN.1/DER according to the following specifications:

  .. code-block:: c
  
    // ASN.1/DER encoding of public key
    PublicKeyInfo ::= SEQUENCE {
      algorithm ::= SEQUENCE {
        algorithm   OBJECT IDENTIFIER,
        parameters  ANY DEFINED BY algorithm OPTIONAL
      }
      PublicKey   BIT STRING
    } // for RSA only PublicKey encodes PKCS#1 `RSAPublicKey`
    
    // ASN.1/DER encoding of private key
    PrivateKeyInfo ::= SEQUENCE {
      version Version,
      algorithm ::= SEQUENCE {
        algorithm   OBJECT IDENTIFIER,
        parameters  ANY DEFINED BY algorithm OPTIONAL
      }
      PrivateKey  BIT STRING
    } // for RSA only, PrivateKey encodes PKCS#1 `RSAPrivateKey`
    
    // ASN.1/DER encoding of encrypted private key
    EncryptedPrivateKeyInfo ::= SEQUENCE {
      encryptionAlgorithm ::= SEQUENCE {
        algorithm   OBJECT IDENTIFIER,
        parameters  ANY DEFINED BY algorithm OPTIONAL
      }
      encryptedData ::= OCTET STRING (encrypts PrivateKeyInfo)
    }
  
(2) The ASN.1 structure is then encoded using Base64/PEM.
(3) The key data is wrapped in a header/footer banner indicating the type of key. These banners may be:

  .. code-block:: c
  
    -----BEGIN PUBLIC KEY-----
    base64-encoded public key
    -----END PUBLIC KEY-----
    
    -----BEGIN PRIVATE KEY-----
    base64-encoded private key
    -----END PRIVATE KEY-----
    
    -----BEGIN ENCRYPTED PRIVATE KEY-----
    base64-encoded encrypted private key
    -----END ENCRYPTED PRIVATE KEY-----
  
  

Structures
_____________

.. doxygenstruct:: cryptx_pkcs8_pubkeyinfo
  :project: CryptX
  :members: _objectid, _publickey
 
Response Codes
_______________
 
.. doxygenenum:: pkcs_error_t
	:project: CryptX
 
Functions
__________
	
.. doxygenfunction:: cryptx_pkcs8_import_publickey
	:project: CryptX

You can import a keyfile and then access its data like so:

.. code-block:: c

  char *fname = "MyKey";
  uint8_t fp;
  
  // load the key from AppVar file
  // requires FILEIOC library
  if(!(fp = ti_Open(fname, "r"))) return;   // failed to open file
  uint8_t *pkcs_data = ti_GetDataPtr(fp);
  size_t pkcs_len = ti_GetSize(fp);
  ti_Close(fp);
  
  pkcs_error_t err;
  cryptx_pkcs8_pubkeyinfo key;
  
  err = cryptx_pkcs8_import_publickey(pkcs_data, pkcs_len, &key);
  if(err) return;
  
  key.objectid.data;       // pointer to object id
  key.objectid.len;        // length of object id
  key.publickey.data;      // pointer to key data (RSA public modulus or ECC pubkey)
  key.publickey.len;       // pointer to length of key data
  key.publickey.exponent;  // public exponent for RSA, unused for ECC


Object Identifier Reference
___________________________

This section lists algorithm object identifiers supported by this library. Developers should generally never need to use these as the library should handle it internally, but if you need them for other projects or even for custom implementations, here they are.

**Bear in mind that while this module can successfully import "objects" for most algorithm types, only the ones listed below can actually be USED by the library.**

+---------------+--------------------------+---------------------------------------+
| Algorithm     | Object Identifier        | Bytes                                 |
+===============+==========================+=======================================+
| RSA           | 1.2.840.113549.1.1.1     | $2A,$86,$48,$86,$F7,$0D,$01,$01,$01   |
+---------------+--------------------------+---------------------------------------+
| EC_SECT233K1  | 1.3.132.0.26             | ??                                    |
+---------------+--------------------------+---------------------------------------+
