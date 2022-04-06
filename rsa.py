from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


def encrypt_message(message , publickey):
	rsa_cipher = PKCS1_OAEP.new(publickey)
	return rsa_cipher.encrypt(message.encode())


def decrypt_message(encrypted_message, privatekey):
	rsa_cipher = PKCS1_OAEP.new(privatekey)
	return rsa_cipher.decrypt(encrypted_message).decode()


keypair = RSA.generate(2048)
public_key = RSA.import_key(keypair.publickey().exportKey())
private_key = RSA.import_key(keypair.exportKey())

message = "NIS4 - A Symmetric Key Distribution Protocol Utilizing Network Steganongraphy"
encrypted_message = encrypt_message(message, public_key)
decrypted_message = decrypt_message(encrypted_message, private_key)

print(f"Message:\t{message}")
print(f"Encrypted:\t{encrypted_message}")
print(f"Decrypted:\t{decrypted_message}")