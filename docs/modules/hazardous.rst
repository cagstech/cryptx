This segment contains lower-level functions that are not part of the standard API. This allows developers who know what they are doing to write their own constructions. Remember that it is generally ill-advised to try to implement your own cryptography.

.. code-block:: c

	#define CRYPTX_ENABLE_HAZMAT	// to enable the hazardous materials
	
.. doxygenfunction:: cryptx_hazmat_aes_ecb_encrypt
	:project: CryptX
	
.. doxygenfunction:: cryptx_hazmat_aes_ecb_decrypt
	:project: CryptX
	
.. doxygenfunction:: cryptx_hazmat_rsa_oaep_encode
	:project: CryptX

.. doxygenfunction:: cryptx_hazmat_rsa_oaep_decode
	:project: CryptX
	
.. doxygenfunction:: cryptx_hazmat_powmod
	:project: CryptX

.. doxygendefine:: CRYPTX_GF2_INTLEN
	:project: CryptX


.. doxygenstruct:: cryptx_ecc_point
	:project: CryptX
	
.. doxygenfunction:: cryptx_hazmat_ecc_point_add
	:project: CryptX
	
.. doxygenfunction:: cryptx_hazmat_ecc_point_double
	:project: CryptX
	
.. doxygenfunction:: cryptx_hazmat_ecc_point_mul_scalar
	:project: CryptX
