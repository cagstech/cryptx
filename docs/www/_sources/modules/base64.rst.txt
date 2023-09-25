.. _base64:

Base64/PEM
============

.. raw:: html

  <p style="background:rgba(176,196,222,.5); padding:10px; font-family:Arial; margin:20px 0;"><span style="font-weight:bold;">Module Functionality</span><br />Provides an encoder and decoder for Base64 (sextet) encoding. PEM is simply a Base64 encoding of DER-encoded data wrapped with banners indicating the type of object that is being encoded. PEM is another encoding format common to cryptography.</p>
  
**Sextet** encoding means that single byte of data encodes six (6) bits of information. Conversion involves parsing an *octet-encoded* (a single byte of data encodes eight (8) bytes of information) stream of data 6 bits at a time, then mapping the resulting value to one of 64 (hence base64) printable characters or the padding character *=*. Reversing this is done by doing these steps in reverse.

You may recognize the following in some files or data dumps you may have seen before. This is PEM.
  
.. code-block:: c
  
    ======BEGIN RSA PUBLIC KEY======
    A couple lines of
    Base64-encoded data
    that contain the RSA
    public key
    ======END RSA PUBLIC KEY======
  
Macros
_______

.. doxygendefine:: cryptx_base64_get_encoded_len
	:project: CryptX
	
.. doxygendefine:: cryptx_base64_get_decoded_len
	:project: CryptX
 
Functions
_________
	
.. doxygenfunction:: cryptx_base64_encode
	:project: CryptX
	
.. doxygenfunction:: cryptx_base64_decode
	:project: CryptX
