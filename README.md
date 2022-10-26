# CRYTPX #

CryptX provides industry-standard cryptography for the TI-84+ CE graphing calculator.
The package contains three(3) separate libraries that serve different functions. 

1. HASHLIB -- provides SHA-256 cryptographic hash, HMAC, MGF1, and PBKDF2_HMAC
2. ENCRYPT -- provides a secure HWRNG, AES, and RSA
3. ENCODEX -- provides support for ASN.1 parsing, Base64 encoding and decoding

These libraries depend on **LIBLOAD**, which is a dynamic library loader provided by the CE C
toolchain. Make sure you have that present on your device.
[CE C toolchain](https://github.com/CE-Programming/toolchain).

If you are an end-user who only needs the library files, you can simply send one or more of the
TI Application Variables--HASHLIB.8xv, ENCRYPT.8xv, ENCODEX.8xv--to your TI-84+ CE.

If you are a developer, you will need to install the necessary files from this library into the 
toolchain's source and library directories in order to use the libraries in your programs. 
To do this you will need to move the library's `.lib` and `.h` files into the correct folders
within the toolchain. The `.lib` files for each library go into the `$CEDEV/lib/libload` directory
and the `.h` files for each library go into the `$CEDEV/include`.

For more detailed documentation head to [Quick Refence](https://github.com/acagliano/cryptx/blob/stable/QuickReference.pdf).
For cryptanalysis head to [Cryptanalysis](https://github.com/acagliano/cryptx/blob/stable/Cryptanalysis.pdf).

Credits:  
Some algorithms sourced at least in part from [B-con crypto-algorithms](https://github.com/B-Con/crypto-algorithms).  
Cemetech user Zeroko - information on CE randomness.  
beckadamtheinventor & commandblockguy - coding assistance, conversion of some C routines to assembly for speed.  
jacobly - modular exponentiation
