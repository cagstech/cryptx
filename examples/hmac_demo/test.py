import hmac,hashlib

string = b"testing12345"
key = b"testpass1"

print(hmac.new(key, string, hashlib.sha256).hexdigest())
