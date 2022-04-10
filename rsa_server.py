import socket, os, rsaClass
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


rsa_class = rsaClass()
rsa_class.generate_keys()

message = get_random_bytes(32)
encrypted_message = rsa_class.encrypt_message(message)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ip_address = input("Enter IP address of client:\t")
sock.connect((ip_address, 12345))
sock.send(encrypted_message)

# For Testing / Comparing
decrypted_message = rsa_class.decrypt_message(encrypted_message)
print(f"Message:\t{message}")
print(f"Encrypted:\t{encrypted_message}")
print(f"Decrypted:\t{decrypted_message}")