import sys
from Cryptodome.Cipher import AES
from Cryptodome.Util import Counter
from enum import Enum

class CipherMode(Enum):
    CBC = 0
    CTR = 1

# Change to MODE = CipherMode.CBC to test CBC mode
MODE = CipherMode.CTR

# edit using the output to cemu console to test output of encryption
key = b"\xEE\x89\x19\xC3\x8D\x53\x7A\xD6\x04\x19\x9E\x77\x0B\xE0\xE0\x4C\x4C\x70\xDB\xE1\x22\x79\xE1\x90\x06\x1B\xAF\x99\x49\x8E\x66\x73"
iv = b"\x79\xA6\xDE\xDF\xF0\xA2\x7C\x7F\xEE\x0B\x8E\xF5\x12\x63\xA4\x8A"
pt1 = b"The lazy fox jumped over the dog!"
pt2 = b"The lazier fox fell down!"
aad = "Some random header"

if MODE==CipherMode.CBC:
    cipher_encrypt = AES.new(key, AES.MODE_CBC, iv=iv)
    cipher_decrypt = AES.new(key, AES.MODE_CBC, iv=iv)
elif MODE==CipherMode.CTR:
    cipher_encrypt = AES.new(key, AES.MODE_CTR, nonce=iv[:8], initial_value=iv[8:])
    cipher_decrypt = AES.new(key, AES.MODE_CTR, nonce=iv[:8], initial_value=iv[8:])
    
# encrypt both messages
cipher_encrypt.update(aad)
ct1 = cipher_encrypt.encrypt(pt1)
ct2 = cipher_encrypt.encrypt(pt2)
print(f"encrypted message 1\n{ct1.hex()}\n")
print(f"encrypted message 2\n{ct2.hex()}\n")

# decrypt both messages to verify
test1 = cipher_decrypt.decrypt(ct1)
test2 = cipher_decrypt.decrypt(ct2)
print(f"decrypted message 1\n{pt1}\n")
print(f"decrypted message 2\n{pt2}\n")


