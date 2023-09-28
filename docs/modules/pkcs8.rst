.. _pkcs8:

PKCS#8
=========

.. raw:: html

  <p style="color:red; font-weight:bold; font-size:120%;">Module under development. Check back for updates.</p><p style="background:rgba(176,196,222,.5); padding:10px; font-family:Arial; margin:20px 0;"><span style="font-weight:bold;">Module Functionality</span><br />Provides functions for the import of PKCS#8-encoded public and private keys that can be used with the RSA and EC modules of this library.</p>

PKCS stands for **Public Key Cryptography Standards** and specification #8 provides general key encoding guidelines for various forms of public and private keys. Because the API of this library tends to work on raw data (rather than on key structures like other libraries do), this module provides a way to deserialize PKCS#8 keyfiles such that you can access components of the key. You can also pass these public and private key structures directly to the TLS implementation (coming soon).

PKCS#8 typically encodes keydata using the following workflow:

(1) The components of the key are encoded using ASN.1/DER. :ref:`Click here <spec>` for more details.
  
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
  
.. doxygenstruct:: cryptx_pkcs8_privkeyinfo
  :project: CryptX
  
.. note::

  These structures, particularly **cryptx_pkcs8_privkeyinfo**, take up a lot of memory. For the private key you're holding 257 bytes each for modulus and exponent and then 7 subfields of efficiency-oriented key metadata each taking 129 bytes plus associated size words, structure headers, and object IDs. It adds up. You may want to allocate these within the largest memory-space you can.
  
Response Codes
_______________
 
.. doxygenenum:: pkcs_error_t
	:project: CryptX
 
Functions
__________
	
.. doxygenfunction:: cryptx_pkcs8_import_publickey
	:project: CryptX
 
.. doxygenfunction:: cryptx_pkcs8_import_privatekey
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
  
  key.objectid.data;       // pointer to object id (bytes)
  key.objectid.len;        // length of object id
  // For RSA
  key.publickey.rsa.data;      // public modulus data (bytes)
  key.publickey.rsa.len;       // length of rsa modulus (size_t)
  key.publickey.rsa.exponent;  // public exponent (uint24_t)
  // For EC
  key.publickey.ec.curveid.data;  // pointer to curve id (bytes)
  key.publickey.ec.curveid.len;   // length of curve id (size_t)
  key.publickey.ec.data;          // public key (bytes)
  key.publickey.ec.len;           // length of public key
  
.. _spec:

PKCS#8 Encoding Specification
______________________________

This section details the PKCS#8 encoding format for public and private key files.

.. code-block:: asn1
    
  PublicKeyInfo ::= SEQUENCE {
    algorithm ::= SEQUENCE {
      algorithm   OBJECT IDENTIFIER,
      parameters  ANY DEFINED BY algorithm OPTIONAL
    }
    PublicKey   BIT STRING
  }

  PrivateKeyInfo ::= SEQUENCE {
    version Version,
    algorithm ::= SEQUENCE {
      algorithm   OBJECT IDENTIFIER,
      parameters  ANY DEFINED BY algorithm OPTIONAL
    }
    PrivateKey  BIT STRING
  }
  
  EncryptedPrivateKeyInfo ::= SEQUENCE {
    encryptionAlgorithm ::= SEQUENCE {
      algorithm   OBJECT IDENTIFIER,
      parameters  ANY DEFINED BY algorithm OPTIONAL
    }
    encryptedData ::= OCTET STRING (encrypts PrivateKeyInfo)
  }
  
For some key formats the *PublicKey* field further encodes a structure from a different standard. This is true for all CryptX use cases of these keys.

.. code-block:: asn1
      
    -- from PKCS#1, src: rfc3447 A.1.1
    RSAPublicKey ::= SEQUENCE {
      modulus         INTEGER,    -- n
      publicExponent  INTEGER,    -- e
    }
    
    -- from PKCS#1, src: rfc3447 A.1.2
    RSAPrivateKey ::= SEQUENCE {
      version           Version,
      modulus           INTEGER,  -- n
      publicExponent    INTEGER,  -- e
      privateExponent   INTEGER,  -- d
      prime1            INTEGER,  -- p
      prime2            INTEGER,  -- q
      exponent1         INTEGER,  -- d mod (p-1)
      exponent2         INTEGER,  -- d mod (q-1)
      coefficient       INTEGER,  -- (inverse of q) mod p
      otherPrimeInfos   OtherPrimeInfos OPTIONAL
    }
    
    -- from SECG1, src: rfc5915 1.3
    ECPrivateKey ::= SEQUENCE {
      version     INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
      privateKey  OCTET STRING,
      parameters  [0] ECParameters {{ NamedCurve }} OPTIONAL,
      publicKey   [1] BIT STRING OPTIONAL
    }
    
    -- from SECG1, src: rfc5915 2.2
    ECPublicKey ::= ECPoint ::= OCTET STRING
    -- first octet of key is 0x04 for uncompressed or 0x03 or 0x02 for compressed

Object Identifier Reference
___________________________

This section lists object identifiers for algorithms supported by this library. Developers should generally never need to use these as the library should handle it internally, but if you need them for other projects or even for custom implementations, here they are.

**Bear in mind that while this module can successfully import objects for most algorithm types, only the ones listed below can actually be USED by the library.**

+----------------+--------------------------+---------------------------------------+
| Algorithm      | Object Identifier        | Bytes                                 |
+================+==========================+=======================================+
| RSA            | 1.2.840.113549.1.1.1     | $2A,$86,$48,$86,$F7,$0D,$01,$01,$01   |
+----------------+--------------------------+---------------------------------------+
| Elliptic Curve | 1.2.840.10045.2.1        | $2A,$86,$48,$CE,$3D,$02,$01           |
+----------------+--------------------------+---------------------------------------+
| EC_SECT233K1   | 1.3.132.0.26             | $2B,$81,$04,$00,$1A                   |
+----------------+--------------------------+---------------------------------------+
