from Cryptodome.PublicKey import RSA

SIZE = 1024

key = RSA.generate(SIZE)
pubkey = bytes(key.public_key().export_key('DER'))
print("\n\n")
print("{", end="")
for x in pubkey:
	print("0x%02x"%x, end=",")
print("}", end="")
