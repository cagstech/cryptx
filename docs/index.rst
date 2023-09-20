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
|`key <key>`_       | implements key generation, export, and import                            |
+-------------------+--------------------------------------------------------------------------+
|`tls <tls>`_       | implements TLS protocol                                                  |
+-------------------+--------------------------------------------------------------------------+

Last but not least, this library implements platform-specific considerations for side-channel attacks to the best extent possible on the hardware. This includes:

* constant-time implementations where possible
* stack frame zeroing after cryptographic transformations
* system interrupts disabled during cryptographic transformations

Check out the :ref:`analysis` for more technical implementation details including platform-specific security considerations.

Most of this library's modules have been tested for compatibility with several other cryptographic libraries including *openssl*, *cryptodome/pycryptodome*, and *cryptography*, although in some cases where libraries do not expose their primitives, use of their *hazardous materials* layer may be required. If you do find an incompatibility with another cryptographic library, please open an issue on the `CryptX Github <https://github.com/acagliano/cryptx>`_.

----

Secure Channel Handshake Process
_________________________________

**Preamble**

  This section is for both end-user and developer alike. Give this section a read if would like a rough understanding of how these modules (in any cryptography library, not just CryptX) come together to ensure your information is protected in transit. It will be a very abbreviated explanation that will barely scratch the surface of the field but should get you pointed in the right direction to understanding how encryption and authentication work. We will use HTTPS as the use-case for explanation.

**Client Says Hi [Insecure]**

  The first step to any communication is to say hi. In the case of HTTPS, this is your web browser telling some website's server that you wish to view a resource it is hosting. This is sent in the clear, as there's no real reason to keep it secret.

**Server Acknowledges [Insecure]**

  Upon receiving your hello, the server will reply with an acknowledgement. For a server running HTTPS, a certificate will soon follow. This certificate contains a shitton of information about the endpoint--hostname, identity of the authority that generated it, various signatures that can be verified--as well as a collection of algorithms and public keys the server will use for secure connections.

**Client Validates Certificate and Selects Algorithms [Insecure]**

  The client will load the certificate itself and will verify the signature(s) on the certificate. In some cases it will also follow the chain of trust back to the issuing authority and verify its signature as well. If these signatures are invalid some browsers will display a "bad certificate" or "insecure connection" warning and others will just refuse to load the content.

  If nothing goes wrong however, the client will consider the choices of algorithms for encryption and choose the best ones available. In some cases this may be RSA with AES-GCM-256. In other cases this may be ECDH with AES-CTR-128. Whatever the case may be, this is then communicated back to the server. The server responds with acknowledgement.

**Go-Go Gadget Public Key Cryptography [Secure]**

  This is the point at which the communication upgrades to a secure connection. The chosen public key encryption algorithm is used to encrypt (or generate) the shared secret. The encrypted message is then sent between the two parties. In the case of RSA, the client tells the server what shared secret it wants to use. In the case of ECDH, both parties exchange public keys and compute the shared secret simultaneously. In both cases, you now have all the information you need for the next phase of secure communication.

**Back and Forth with AES [Secure]**

  The major heavy lifting for this is done now and both parties have a shared secret--an AES key, if you will. Both parties open an AES session under that key and begin to talk to each other. This continues until:
  
    - You hit a stupidly large amount of data encrypted on a single key at which point the encryption algorithm may begin to leak bits of the key. For most AES cipher modes this occurs at about :code:`(2 ^ 64) * 16` bytes of data encrypted. For other cipher modes this can be as low as :code:`(2 ^ 24) * 16` bytes but it is still a number you will never realisticlly hit, especially on a calculator. If for some ridiculous reason you do hit this, you fallback to public key cryptography to negotiate a new AES secret.
    
    - One of the parties disconnects.
  
----

The TLS Protocol
_________________
When computer scientists start throwing out fancy acronyms, they may sound scary but it's usually just appearances. TLS stands for **Transport Layer Security** and, much like the horror movie villain who becomes a lot less scary when you realize you can probably outrun him, TLS gets less scary when we discover what it is. All TLS does is protocolize the handshake process we have previously discussed. You may see some code that looks similar to this.

.. code:: c

  socket_t sock = socket_create();
  tls_socket_t ssock = tls_wrap_socket(sock);
  ssock.send(data);
  ssock.recv(data);

The code creates a standard socket object, then calls a TLS socket wrapper method. This method not only returns an encrypted socket object but also handles the requisite handshaking on a shared secret. Do you NEED to use TLS? I mean technically, no. You can do the handshake in parts, like you have to with CryptX until TLS is implemented. However, protocols like TLS are recommended (and many times enforced) because cryptography is kind of like that scene from Avengers: Infinity War. There's 14,000,605 ways to get it wrong and only one way to get it right. To this end I strongly advise that developers using CryptX update their applications to make use of TLS within CryptX instead of manual handshaking as soon as that module is implemented and stable.




Additional Resources
---------------------
.. toctree::
    :maxdepth: 1

    static/analysis
