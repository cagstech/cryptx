.. _csrand:

secure random number generator
===============================

Encryption requires the ability to generate random artifacts [#d1]_ for use as keys, nonces, and salts. The non-intractibility [#d2]_ of modern encryption depends almost entirely on the ability to generate secure randomness within your cryptosystem. Many random number generators, such as the :code:`rand()` function in the toolchain, are statistically-random and deterministic [#d3]_. This suffices for your Solitare app's card stack but not for generating an encryption key.

Generators intended for use with cryptography need to operate within additional constraints centered around unpredictability. Their output must be indistinguishable from truly random (giving an attacker negligibly better odds than that of predicting any bit of a truly random sequence). Additionally, compromise of the generator's state (i.e. seed or other state information) should not compromise the effective security of the generator. The generator provided by this library meets those constraints. For details, see the :ref:`Analysis & Overview <analysis>` page.

**Terms Defined**

.. [#d1] **random artifact**: another term for a bytearray containing random bytes.

.. [#d2] **non-intractibility**: difficulty in solving or reversing.

.. [#d3] **statistically-random**: random data appears to have a uniform distribution over all possible values; **deterministic**: a single input maps to a single output that can be easily computed, meaning this not suitable for anything needing secrecy.

----

Functions
__________

.. doxygenfunction:: cryptx_csrand_get
	:project: CryptX
 
.. code-block:: c
  
  // returning a single 32-bit random integer
  uint32_t rand = cryptx_csrand_get();
  

.. doxygenfunction:: cryptx_csrand_fill
	:project: CryptX
 
.. code-block:: c
  
  // filling a buffer with random bytes
  #define BUFLEN  16
  uint8_t rand[BUFLEN];
  cryptx_csrand_fill(rand, BUFLEN);
