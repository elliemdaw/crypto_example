# starting from https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256

import sys
import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):

    def __init__(self, key): 
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


def main():
	if str(sys.argv[1]) == "help":
		print("\nUsage:\npython aes.py <enc|dec> <key> <data>\n")
		exit(0)

	cipher_obj = AESCipher(sys.argv[2])

	if str(sys.argv[1]) == "enc":
		data = cipher_obj.encrypt(sys.argv[3])
		action = "encrypted"
	elif str(sys.argv[1]) == "dec":
		data = cipher_obj.decrypt(sys.argv[3])
		action = "decrypted"

	print("\nHere is " + str(sys.argv[3]) + " " + action + " using the key " + str(sys.argv[2]) + ":")
	print(data + "\n")


if __name__ == "__main__":
	main()
