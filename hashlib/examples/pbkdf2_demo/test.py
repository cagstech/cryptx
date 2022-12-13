import hmac,hashlib


passwd = b"testing123"
salt = b"\xea\x53\xad\xb5\x34\x96\xdc\xdd\xd9\xd8\xf1\x50\x4c\x9d\xfb\x4d"
print(hashlib.pbkdf2_hmac('sha256', passwd, salt, 10, dklen=64).hex())
