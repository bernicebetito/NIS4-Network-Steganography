import socket, os, rsaClass
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


rsa_class = rsaClass.rsaClass()
rsa_class.generate_keys()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ip_address = input("Enter IP address of client:\t")
sock.bind((ip_address, 5555))
data = sock.recvfrom(1024)

print(f"Data Received:\t{data}\n\n")

decrypted_message = rsa_class.decrypt_message(data[0])
print(f"Decrypted:\t{decrypted_message}")
