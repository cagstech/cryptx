CryptX Library
================
**Industry-Standard Cryptography for the Texas Instruments TI-84+ CE Graphing Calculator**

.. raw:: html

  <p style="background:rgba(176,196,222,.5); padding:10px; font-family:Arial; margin:20px 0;"><span style="font-weight:bold;">Cryptography</span> is a specialization within the information security field that deals almost exclusively with protecting data from being read or modified by unauthorized parties. Cryptographic standards are vigorously tested for vulnerabilities and subject to constant analysis and improvement.</p>

**CryptX** is a specialty library designed to provide cryptographic functionality for the TI-84+ CE. It integrates with the `CE C toolchain <https://github.com/CE-Programming/toolchain>`_ and allows developers to easily implement cryptography into their projects without needing to worry about low-level implementation details. Distribution as a dynamic library also allows for the library to be updated with new functionality, bug fixes, and vulnerability patches usually without even requiring programs be rebuilt. Just install the new library version on your device and it should be forwards-compatible.

**CryptX** was made possible thanks to the work of a number of individuals from the `Cemetech <https://www.cemetech.net/>`_ development community. From code contributions to lengthy discussions about ways and means to analysis of hardware behavior, this project would not have evolved into what it became without their support.

+-----------------------+---------------------------------------------------------------------+
| Contributor           | Contribution                                                        |
+=======================+=====================================================================+
| Anthony Cagliano      | lead developer, main algorithm implementation/sourcing              |
+-----------------------+---------------------------------------------------------------------+
| Adam Beckingham       | porting to ez80 assembly and optimizing many algorithms             |
+-----------------------+---------------------------------------------------------------------+
| John Caesarz          | general code contributions                                          |
+-----------------------+---------------------------------------------------------------------+
| jacobly               | general code contributions                                          |
+-----------------------+---------------------------------------------------------------------+
| Zeroko                | info and analysis for entropic RNG construction                     |
+-----------------------+---------------------------------------------------------------------+
| calc84maniac          | general code contributions                                          |
+-----------------------+---------------------------------------------------------------------+
| MateoConLechuga       | words of encouragement, incl. "That's not how RSA works, you idiot" |
+-----------------------+---------------------------------------------------------------------+

Most of this library's modules have been tested for compatibility with several other cryptographic libraries including *openssl*, *cryptodome/pycryptodome*, and *cryptography*, although in some cases where libraries do not expose their primitives, use of their *hazardous materials* layer may be required. If you do find an incompatibility with another cryptographic library, please open an issue on the `CryptX Github <https://github.com/acagliano/cryptx>`_.

----

API Documentation
^^^^^^^^^^^^^^^^^^

CryptX has a number of modules that implement various standards for data obfuscation and integrity verification. The library attempts to evidence this by utilizing the following function naming convention:

.. code:: c
  
  cryptx_[module]_[method]
  
+-------------------+--------------------------------------------------------------------------+
| Module            | Implements                                                               |
+===================+==========================================================================+
|`csrand <csrand>`_ | implements cryptographically-secure random number generation             |
+-------------------+--------------------------------------------------------------------------+
|`digest <digest>`_ | implements digest manipulation                                           |
+-------------------+--------------------------------------------------------------------------+
|`hash <hash>`_     | implements hashing                                                       |
+-------------------+--------------------------------------------------------------------------+
|`hmac <hmac>`_     | implements hash-based message authentication code (hmac)                 |
+-------------------+--------------------------------------------------------------------------+
|`aes <aes>`_       | implements advanced encryption standard (aes)                            |
+-------------------+--------------------------------------------------------------------------+
|`rsa <rsa>`_       | implements RSA public key cryptography                                   |
+-------------------+--------------------------------------------------------------------------+
|`ecdh <ecc>`_      | implements elliptic curve diffie-hellman (ecdh) key exchange             |
+-------------------+--------------------------------------------------------------------------+
|`asn1 <encoding>`_ | implements decoder for DER/ASN.1 encoding                                |
+-------------------+--------------------------------------------------------------------------+
|`base64 <base64>`_ | implements encoder/decoder for PEM/base64 encoding                       |
+-------------------+--------------------------------------------------------------------------+

+-------------------+--------------------------------------------------------------------------+
| Coming Soon       | Implements                                                               |
+===================+==========================================================================+
|`ecdsa <ecc>`_     | implements elliptic curve digital signing algorithm (ecdsa)              |
+-------------------+--------------------------------------------------------------------------+
|`key <key>`_       | implements importing and exporting keys for various formats              |
+-------------------+--------------------------------------------------------------------------+
|`tls <tls>`_       | implements TLS protocol                                                  |
+-------------------+--------------------------------------------------------------------------+

To avoid text overload, the entire library documentation will not be dumped onto a single page. You may click on the links in the table above if you wish to view more detailed documentation for a particular module.

----

Security Considerations
^^^^^^^^^^^^^^^^^^^^^^^^

Last but not least, this library implements platform-specific considerations for side-channel attacks to the best extent possible on the hardware. This includes:

* constant-time implementations where possible
* stack frame zeroing after cryptographic transformations
* system interrupts disabled during cryptographic transformations

Check out the :ref:`analysis` for more technical implementation details including platform-specific security considerations.

----


Additional Resources
---------------------
.. toctree::
    :maxdepth: 1

    static/analysis
