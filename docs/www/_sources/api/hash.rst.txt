.. _hash:

Secure Hashing
===============

.. raw:: html

  <p style="background:rgba(176,196,222,.5); padding:10px; font-family:Arial; margin:20px 0;"><span style="font-weight:bold;">Module Functionality</span><br />Provides secure hashing functionality. Hashes are non-reversible cryptographic algorithms that take a stream of bytes as input and return a bytearray of fixed length called a digest. Hashes are also deterministic &mdash; a single input maps to a single output &mdash; meaning that if the input changes, even slightly, the digest also changes. A hash can detect if the content of something &mdash; like a file or an Internet packet &mdash; changes and reveal tampering if the change was not authorized.</p>
  
  
Enumerations
_______________

.. doxygenenum:: cryptx_hash_algorithms
	:project: CryptX
 
Functions
_______________

.. doxygenfunction:: cryptx_hash_init
	:project: CryptX
	
.. doxygenfunction:: cryptx_hash_update
	:project: CryptX
	
.. doxygenfunction:: cryptx_hash_digest
	:project: CryptX

----

.. doxygenfunction:: cryptx_hash_mgf1
	:project: CryptX


**Notes**

  (1) After initialization the hash context holds the digest length for the selected algorithm. You can read it by accessing :code:`context.digest_len`. **This is the only reason you should be accessing a member of the hash context.**
  (2) This API uses 516 bytes of *fastMem* starting at :code:`0xE30800` for scratch memory. Do not use it for anything else if you are using this API.
