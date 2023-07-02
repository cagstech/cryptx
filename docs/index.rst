Cryptography for the CE
==================================

**CryptX** is a specialty library designed for integration with the TI-84+ CE toolchain that allows developers to easily implement cryptography into their projects without needing to worry about low-level implementation details. It also allows for bugfixes, feature additions, and changes to be pushed to the library usually without requiring developers to rebuild their projects.

If this is your first introduction to the CE Toolchain, check out the `toolchain repository <https://github.com/CE-Programming/toolchain>`_ and familiarize yourself with how it works.

You may be asking yourself "What makes CryptX any different than the many other tools on various forums claiming to hide or encrypt programs?". In most cases those tools do not perform actual encryption but merely set a flag preventing the average person from seeing the programs. This does not prevent viewing, or even modification, of the data comprising those programs. This utility provides **actual** encryption. The following is an exhaustive list of what CryptX provides.

	- Hashing (Hash, HMAC, MGF1)
	- Password-Based Key Derivation
	- Secure Random Number Generation
	- Advanced Encryption Standard
	- Rivest-Shamir Adleman (RSA)
	- Elliptic Curve Diffie-Hellman (implements SECT233k1)
	- Abstract Syntax Notation One (ASN.1) and Base64 decoding
	- Timing-safe buffer comparison
	
Need more convincing? Check out the :ref:`analysis` for more technical implementation details including platform-specific security considerations.

Most of this library's modules have been tested for compatibility with several other cryptographic libraries including *openssl*, *cryptodome/pycryptodome*, and *cryptography*, although in some cases where libraries do not expose their primitives, use of their *hazardous materials* layer may be required. If you do find an incompatibility with another cryptographic library, please open an issue on the `CryptX Github <https://github.com/acagliano/cryptx>`_.


Additional Resources
^^^^^^^^^^^^^^^^^^^^^
.. toctree::
    :maxdepth: 1

    static/analysis
    
    



