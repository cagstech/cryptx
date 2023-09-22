.. _bytes:

Bytearray Operations
=====================

.. raw:: html

  <p style="background:rgba(176,196,222,.5); padding:10px; font-family:Arial; margin:20px 0;"><span style="font-weight:bold;">Module Functionality</span><br />Provides bytearray handling including: conversion between raw bytes and hex-encoded strings, reversing the endianness of a bytearray, and a constant-time method of comparing buffers.</p>


Functions
__________

.. doxygenfunction:: cryptx_bytes_compare
	:project: CryptX
 
.. code-block:: c

  cryptx_bytes_compare(buf1, buf2, bytes_to_compare);

----

.. doxygenfunction:: cryptx_bytes_tostring
	:project: CryptX
 
.. code-block:: c

  // assume `arr` is a bytearray
    
  // allocate buffer for string twice length of bytearray
  // plus an addition byte for null termination
  char hexstr[sizeof(arr) * 2 + 1];
    
  cryptx_bytes_tostring(arr, sizeof(arr), hexstr);

----

.. doxygenfunction:: cryptx_bytes_rcopy
  :project: CryptX

.. doxygenfunction:: cryptx_bytes_reverse
  :project: CryptX
  
.. code-block:: c

  // assume `arr1` is a bytearray
  // assume `arr2` is another reserved buffer of same length
    
  // makes a copy of arr2 with byteorder reversed
  cryptx_bytes_rcopy(arr2, arr1, sizeof(arr2));
    
  // reverses arr1 in-place
  cryptx_bytes_reverse(arr1, sizeof(arr1));

----
