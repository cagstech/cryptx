.. _pkcs8:

PKCS#8
=========

.. raw:: html

  <p style="color:red; font-weight:bold; font-size:120%;">Module under development. Check back for updates.</p><p style="background:rgba(176,196,222,.5); padding:10px; font-family:Arial; margin:20px 0;"><span style="font-weight:bold;">Module Functionality</span><br />Provides functions for the import of PKCS#8-encoded public and private keys that can be used with the RSA and EC modules of this library.</p>
  <br />
  <p style="background:rgba(128,128,128,.25); padding:10px; font-family:Arial; font-size:14px;"><span style="font-weight:bold;">#cryptxdevquotes:</span> <span style="font-style:italic;">The allocation for this structure needs more space than exists on the calculator. How is this even working?</span>&emsp;- Anthony Cagliano</p>

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
  
Enumerations
_____________
  
.. doxygenenum:: _pkcs8_pubkey_rsa_fields

.. doxygenenum:: _pkcs8_pubkey_ec_fields

.. doxygenenum:: _pkcs8_privkey_rsa_fields

.. doxygenenum:: _pkcs8_privkey_ec_fields

Structures
_____________

.. doxygenstruct:: cryptx_pkcs8_pubkey
  :project: CryptX
  :members:
  
.. doxygenstruct:: cryptx_pkcs8_privkey
  :project: CryptX
  :members:
  
.. note::

  These structures, particularly **cryptx_pkcs8_privkey**, take up a lot of memory. This module uses dynamic allocation to optimize storage requirements for these structures to the best extent possible. Each structure contains a static portion which contains references to a dump of the raw data of the key and the dump section is of variable size depending on the size of the key.
 
Functions
__________
	
.. doxygenfunction:: cryptx_pkcs8_import_publickey
	:project: CryptX
 
.. doxygenfunction:: cryptx_pkcs8_import_privatekey
	:project: CryptX
 
.. doxygenfunction:: cryptx_pkcs8_free_publickey
	:project: CryptX
 
.. doxygenfunction:: cryptx_pkcs8_free_privatekey
	:project: CryptX
 
.. note::

  Remember to call the corresponding *free* method for any structure allocated with the module or you may wind up with memory leaks.

----

You can import your keyfiles like so:

.. code-block:: c

  // assume that you have generated a keypair using openssl or some similar software
  // then converted to appvars 'MyPub' and 'MyPriv' using convbin,
  // then transferred both to your calculator
  char *pubkey_fname = "MyPub";
  char *privkey_fname = "MyPriv";
  uint8_t fp;
  uint8_t *key_data;
  size_t key_len;
  
  // load pubkey from file (requires FILEIOC library)
  if(!(fp = ti_Open(pubkey_fname, "r"))) {
    printf("File IO Error");
    exit(1);
  }
  key_data = ti_GetDataPtr(fp);
  key_len = ti_GetSize(fp);
  ti_Close(fp);
  cryptx_pkcs8_pubkey *pub = cryptx_pkcs8_import_publickey(key_data, key_len, malloc);
  if(!pub){
    printf("Alloc error!");
    exit(2);
  }
  if(pub->error) {
    printf("Deserialization error!");
    exit(3);
  }
  
  // load pubkey from file (requires FILEIOC library)
  if(!(fp = ti_Open(privkey_fname, "r"))) {
    printf("File IO Error");
    exit(1);
  }
  key_data = ti_GetDataPtr(fp);
  key_len = ti_GetSize(fp);
  ti_Close(fp);
  cryptx_pkcs8_privkey *priv = cryptx_pkcs8_import_privatekey(key_data, key_len, malloc);
  if(!priv){
    printf("Alloc error!");
    exit(2);
  }
  if(priv->error) {
    printf("Deserialization error!");
    exit(3);
  }
  
  // these structs can be passed directly to the TLS implementation (coming soon)
  // or the members can be accessed directly for advanced usage.
  
  
.. _spec:

Additional Info
________________

PKCS#8 Specification
^^^^^^^^^^^^^^^^^^^^^

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
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This section lists object identifiers for algorithms supported by this library. Developers should generally never need to use these as the library should handle it internally, but if you need them for other projects or even for custom implementations, here they are.

**Bear in mind that while this module can successfully import objects for most algorithm types, only the ones listed below can actually be USED by the library.**

.. doxygenvariable:: cryptx_pkcs8_objectid_rsa
  :project: CryptX

.. doxygenvariable:: cryptx_pkcs8_objectid_ec
  :project: CryptX

.. doxygenvariable:: cryptx_pkcs8_curveid_sect233k1
  :project: CryptX
