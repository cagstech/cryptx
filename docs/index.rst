Cryptography for the CE
==================================

.. note::
 
  **Cryptography** is a specialization within the field of information security that deals specifically with preventing data from being read or modified in storage or in transit.

**CryptX** is a specialty library designed for integration with the TI-84+ CE toolchain that allows developers to easily implement cryptography into their projects without needing to worry about low-level implementation details. It also allows for bugfixes, feature additions, and changes to be pushed to the library usually without requiring developers to rebuild their projects.

If this is your first introduction to the CE Toolchain, check out the `toolchain repository <https://github.com/CE-Programming/toolchain>`_ and familiarize yourself with how it works.

**CryptX** is not some fever-dream that tinkers with some flags and calls it "encryption" like many of the other programs submitted to such archives as ticalc.org. It was the result of months of tedious work on the part of multiple individuals, analysis on the hardware, testing, and research to create a utility worthy of the name *cryptography library*. This utulity provides:

* Secure Random Number Generation
* Integrity Verification
* Encryption & Key Exchange
* (Password-Based) Key Derivation
* Cryptographic Encoding (ASN.1, Base64)

Last but not least, this library implements platform-specific considerations for side-channel attacks to the best extent possible on the hardware. This includes:

* constant-time implementations where possible
* stack frame zeroing after cryptographic transformations
* system interrupts disabled during cryptographic transformations

Planned feature additions include:

* ECDSA (and possibly RSA) signing
* SSL/TLS protocol to simplify cipher setup and handshakes (this will be done after sockets implemented)

Check out the :ref:`analysis` for more technical implementation details including platform-specific security considerations.

Most of this library's modules have been tested for compatibility with several other cryptographic libraries including *openssl*, *cryptodome/pycryptodome*, and *cryptography*, although in some cases where libraries do not expose their primitives, use of their *hazardous materials* layer may be required. If you do find an incompatibility with another cryptographic library, please open an issue on the `CryptX Github <https://github.com/acagliano/cryptx>`_.


Additional Resources
---------------------
.. toctree::
    :maxdepth: 1

    api
    static/analysis
    static/notes
