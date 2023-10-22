.. _asn1:

ASN.1/DER
==========

.. raw:: html

  <p style="background:rgba(176,196,222,.5); padding:10px; font-family:Arial; margin:20px 0;"><span style="font-weight:bold;">Module Functionality</span><br />Provides a decoder for Abstract Syntax Notation One (ASN.1) encoding. This module allows programs to decode keyfiles using Distinguished Encoding Rules (DER), a serialization of ASN.1 standardized for cryptography.</p>
  
ASN.1 encoding uses a series of tag-length-data pairs. The value may sometimes encapsulate other similarly encoded objects. For example, take a look at the PKCS#8 format for an RSA public key as well as some corresponding hexdump output:

.. code-block:: asn1

  PublicKeyInfo ::= SEQUENCE {
    algorithm ::= SEQUENCE {
      algorithm   OBJECT IDENTIFIER,
      parameters  ANY DEFINED BY algorithm OPTIONAL
    }
    PublicKey   BIT STRING
  }

.. code-block:: hexdump

  30 81 9f
     30 0d
        06 09   2a 86 48 86 f7 0d 01 01 01
      05 00
    03 81 8d    00 30 81 89 02 81 81 00 c0 3c a0 1c  0b 0e be b0 64 62 fc 2e 0e 8d 04 9d
                c1 a7 c7 ce 88 8d 85 87 6a 41 93 45  25 23 25 38 74 ce 4f f1 46 f5 3b 94
                19 b2 1d 6d fc a0 46 04 64 c6 b2 33  77 2f b9 89 33 6a ce 84 8a 5a ff 88
                1f 03 38 31 1d e6 08 dd d0 ae 86 fd  f5 d9 25 4f 82 1c 93 a4 cc 32 22 67
                a2 16 68 b9 d6 ae e4 b2 ee 80 93 b1  4a 2b 80 27 27 fd 99 18 90 b6 e2 97
                2a 14 51 02 ca 73 36 41 52 18 dc a8  e8 69 44 09 02 03 01 00 01
                    
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
	
The ASN.1 tag is an octet consisting of three (3) parts, (1) A 5-bit tag value which is one of the items in the *cryptx_asn1_tags* enum above, (2) A 2-bit class value which is one of the items in the *cryptx_asn1_classes* enum, and (3) a 1-bit form indicating if the item is constructed [encapsulates other encoded elements] or primitive [contains no encapsulated data].

.. doxygendefine:: cryptx_asn1_gettag
	:project: CryptX
	
.. doxygendefine:: cryptx_asn1_getclass
	:project: CryptX
	
.. doxygendefine:: cryptx_asn1_getform
	:project: CryptX
 
Structures
_______________

.. doxygenstruct:: cryptx_asn1_object
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
