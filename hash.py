import sys
from Crypto.Hash import SHA256

h = SHA256.new()
h.update(sys.argv[1])
print("\n" + h.hexdigest() + "\n")
