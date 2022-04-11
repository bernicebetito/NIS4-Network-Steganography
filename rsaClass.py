from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import os


class rsaClass():
	def generate_keys(self):
		public_path = r"public_key.pem"
		private_path = r"private_key.pem"

		ispublic = os.path.exists(public_path)
		isprivate = os.path.exists(private_path)

		if ispublic is False or isprivate is False:
			keypair = RSA.generate(2048)
			public_key = keypair.publickey().exportKey()
			private_key = keypair.exportKey()
			print(f"Warning: New Key Pair Generated. Ensure that receiver has the updated private key.\n\n")

			with open("public_key.pem", "wb") as file:
				file.write(public_key)
				file.close()

			with open("private_key.pem", "wb") as file:
				file.write(private_key)
				file.close()

	def encrypt_message(self, message):
		with open("public_key.pem", "rb") as file:
			publickey = file.read()
		imported_public = RSA.import_key(publickey)
		rsa_cipher = PKCS1_OAEP.new(imported_public)
		return rsa_cipher.encrypt(message)

	def decrypt_message(self, encrypted_message):
		with open("private_key.pem", "rb") as file:
			privatekey = file.read()
		imported_private = RSA.import_key(privatekey)
		rsa_cipher = PKCS1_OAEP.new(imported_private)
		return rsa_cipher.decrypt(encrypted_message)