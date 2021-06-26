# hashlib-stable

This is the stable branch of the TI-84+ CE toolchain library HASHLIB.\s\s
To build this library yourself, navigate into the `src` directory of the CE C toolchain.\s\s
Once in there, run `git clone https://github.com/acagliano/hashlib-stable.git hashlib`.\s\s
cd into that directory and run `make`. HASHLIB should be created.\s\s

Of course there's no need to actually do this, because an up to date build of HASHLIB is provided in this repository.\s\s
To use it with the toolchain, simply send `HASHLIB.8xv` to your device, move `hashlib.lib` into `$CEDEV/lib/libload` and then `hashlib.h` into `$CEDEV/include`\s\s
Once that is done, simply `#include <hashlib.h>` in your project source and you can use all the cryptography functions in the library.\s\s

This library provides the following implementations tested and working on the TI-84+ CE.\s\s

<> A Secure PRNG with a calculated entropy of ~107.1 bits per 32-bit random number and an evaluated advantage negligibly greater than zero.\s\s
<> A 128, 192, and 256 bit AES implementation, in CBC mode.\s\s
<> ** Work in Progress ** 1024-bit RSA, encryption-only\s\s
<> SHA-1 and SHA-256 cryptographic hashes (these guys are a bit on the slow side)\s\s
<> A helper function to pad plaintexts for encryption. Pass plaintext, an output buffer of appropriate size (macros to return that size\s\s included), the algorithm, and a padding spec (or SCHM_DEFAULT). The following padding methods are available:\s\s
    - SCHM_PKCS7 : AES padding, Pad with padding size [DEFAULT FOR AES]\s\s
    - SCHM_ISO_M2 : AES padding, Pad with [0x80, 0x00, ..., 0x00]\s\s
    - SCHM_ISO_M1 : AES padding, Pad with [0x00, ..., 0x00]\s\s
    - SCHM_ANSIX923 : AES padding, Pad with [randbytes]\s\s
    - SCHM_RSA_OAEP : RSA padding, uses the OAEP padding scheme. SHA-256 is the hash used, and it is applied cyclically to the plaintext.\s\s
<> A function to zero out a context that you no longer are using to prevent state leak\s\s
<> Base64 encoding and decoding functions\s\s

Credits:\s\s
Some algorithms sourced at least in part from https://github.com/B-Con/crypto-algorithms. \s\s
Cemetech user Zeroko - information on CE randomness\s\s
beckadamtheinventor & commandblockguy - coding assistance, conversion of some C routines to assembly for speed\s\s
