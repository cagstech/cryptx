from Crypto.Cipher import AES
from Crypto.Util import Counter
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

if MODE==CipherMode.CBC:
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
elif MODE==CipherMode.CTR:
    counter = Counter.new(64, prefix=iv[0:8], suffix=b'', initial_value=int.from_bytes(iv[8:], 'big'), little_endian=False, allow_wraparound=False)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
pt1 = cipher.encrypt(pt1)
pt2 = cipher.encrypt(pt2)

print(f"decrypted message 1\n{pt1.hex()}\n")
print(f"decrypted message 2\n{pt2.hex()}\n")


