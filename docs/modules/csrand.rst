.. _csrand:

Secure Random Number Generator
===============================

.. raw:: html

  <p style="background:rgba(176,196,222,.5); padding:10px; font-family:Arial; margin:20px 0;"><span style="font-weight:bold;">Module Functionality</span><br />Provides secure randomness that can be used for the creation of random artifacts &mdash; encryption secrets, salts, and nonces &mdash; for use with other modules.</p>
  <br />
  <p style="background:rgba(128,128,128,.25); padding:10px; font-family:Arial; font-style:italic; font-size:14px;"><span style="font-weight:bold;">#cryptxdevquotes:</span>&emsp;<span style="font-style:italic;">The new entropy-pooling algorithm for this generator produces about 20% more entropy. In related news, I have 20% less sanity today.</span><br /> -Anthony Cagliano</p>

The security of modern encryption depends almost entirely on the ability to generate secure randomness within your cryptosystem. Many random number generators, such as the :code:`rand()` function in the toolchain, only *appear* random but are actually **deterministic**--a single output maps to a single computable output. This may suffice for your Solitare app's card stack but not for generating an encryption key. Generators intended for use with cryptography need to operate within additional constraints centered around unpredictability. For details on what this means, as well as to view how this generator holds up, see the :ref:`Analysis & Overview <analysis>` page.


Functions
__________

.. doxygenfunction:: cryptx_csrand_get
	:project: CryptX
 
.. code-block:: c
  
  // returning a single 32-bit random integer
  uint32_t rand = cryptx_csrand_get();
  
----

.. doxygenfunction:: cryptx_csrand_fill
	:project: CryptX
 
.. code-block:: c
  
  // filling a buffer with random bytes
  #define BUFLEN  16
  uint8_t rand[BUFLEN];
  cryptx_csrand_fill(rand, BUFLEN);
