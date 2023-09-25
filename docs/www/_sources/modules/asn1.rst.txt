.. _asn1:

ASN.1/DER
==========

.. raw:: html

  <p style="background:rgba(176,196,222,.5); padding:10px; font-family:Arial; margin:20px 0;"><span style="font-weight:bold;">Module Functionality</span><br />Provides a decoder for Abstract Syntax Notation One (ASN.1) encoding. This module allows programs to decode keyfiles using Distinguished Encoding Rules (DER), a serialization of ASN.1 standardized for cryptography.</p>
  
ASN.1 encoding uses a series of tag-length-data pairs. The value may sometimes encapsulate other similarly encoded objects. For example, take a look at the PKCS#8 format for an RSA public key:

.. code-block:: c

  PublicKeyInfo ::= SEQUENCE {
    algorithm ::= SEQUENCE {
      algorithm   OBJECT IDENTIFIER,
      parameters  ANY DEFINED BY algorithm OPTIONAL
    }
    PublicKey   BIT STRING
  }

Now take a look at some scary-looking DER-encoded key data and see how it all breaks down to something discernable.

.. code-block:: c

  PublicKeyInfo   0x30,0x81,0x9f    ; tag = 0x16, constructed = 1, size = 0x9f = 159
    algorithm       0x30,0x0d       ; tag = 0x16, constructed = 1, size = 0x0d = 13
      algorithm       0x06,0x09     ; tag = 0x06, size = 0x09 = 9
                        0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01
      parameters      0x05,0x00     ; tag = 0x05, size = 0, NULL
    PublicKey     0x03,0x81,0x8d    ; tag = 0x03, size = 0x8d = 141
                    0x00,0x30,0x81,0x89,0x02,0x81,0x81,0x00,0xc0,0x3c,0xa0,0x1c,
                    0x0b,0x0e,0xbe,0xb0,0x64,0x62,0xfc,0x2e,0x0e,0x8d,0x04,0x9d,
                    0xc1,0xa7,0xc7,0xce,0x88,0x8d,0x85,0x87,0x6a,0x41,0x93,0x45,
                    0x25,0x23,0x25,0x38,0x74,0xce,0x4f,0xf1,0x46,0xf5,0x3b,0x94,
                    0x19,0xb2,0x1d,0x6d,0xfc,0xa0,0x46,0x04,0x64,0xc6,0xb2,0x33,
                    0x77,0x2f,0xb9,0x89,0x33,0x6a,0xce,0x84,0x8a,0x5a,0xff,0x88,
                    0x1f,0x03,0x38,0x31,0x1d,0xe6,0x08,0xdd,0xd0,0xae,0x86,0xfd,
                    0xf5,0xd9,0x25,0x4f,0x82,0x1c,0x93,0xa4,0xcc,0x32,0x22,0x67,
                    0xa2,0x16,0x68,0xb9,0xd6,0xae,0xe4,0xb2,0xee,0x80,0x93,0xb1,
                    0x4a,0x2b,0x80,0x27,0x27,0xfd,0x99,0x18,0x90,0xb6,0xe2,0x97,
                    0x2a,0x14,0x51,0x02,0xca,0x73,0x36,0x41,0x52,0x18,0xdc,0xa8,
                    0xe8,0x69,0x44,0x09,0x02,0x03,0x01,0x00,0x01
                    
Note how in some of the tag-length-data groups there is a prefix byte of :code:`0x81` (or similar) between the tag and the data length that seems to do nothing. It is actually a serialization of the size word. For a data size of more than 128 bytes a signed byte prefixes the size word indicating the length of the size word. If the size would require three (3) bytes, for example, then the byte :code:`0x83` would prefix it instead.
  

Enumerations
_____________

.. doxygenenum:: cryptx_asn1_tags
	:project: CryptX
	
.. doxygenenum:: cryptx_asn1_classes
	:project: CryptX
	
.. doxygenenum:: cryptx_asn1_forms
	:project: CryptX
 
Macros
_______
	
The ASN.1 tag is an octet consisting of three (3) parts, (1) A 5-bit tag value which is one of the items in the *cryptx_asn1_tags* enum above, (2) A 2-bit class value wich is one of the items in the *cryptx_asn1_classes* enum, and (3) a 1-bit form indicating if the item is constructed [encapsulates other encoded-elements] or primitive [contains no encapsulated data].

.. doxygendefine:: cryptx_asn1_gettag
	:project: CryptX
	
.. doxygendefine:: cryptx_asn1_getclass
	:project: CryptX
	
.. doxygendefine:: cryptx_asn1_getform
	:project: CryptX
	
Response Codes
_______________
 
.. doxygenenum:: asn1_error_t
	:project: CryptX
 
Functions
__________
	
.. doxygenfunction:: cryptx_asn1_decode
	:project: CryptX

Here is a simple example of how to loop each element in an ASN.1 structure and return its metadata. Note how a return value of ASN1_END_OF_FILE is used as a limiter. Also notice that this does not process any constructed objects (such as contents of SEQUENCE or SET objects). To add recursion, simply check the value of bit 5 and if it is set, call a function to process that tag's data using :code:`data` and :code:`data_len` as your *data_start* and *data_len* arguments, respectively.

.. code-block:: c

  // assume `asn1_data` is some imported data encoded with ASN.1
  
  asn1_error_t err = ASN1_OK;
  uint8_t index = 0, tag, *data;
  size_t data_len;
  
  do {
    err = cryptx_asn1_decode(asn1_data, sizeof(asn1_data), index++, &tag, &data_len, &data);
    if(err == ASN1_OK)
      printf("element -- tag:%u, len:%u, data:%p\n", tag, data_len, data);
    else
      printf("error code: %u", err);
  } while(err != ASN1_END_OF_FILE);
