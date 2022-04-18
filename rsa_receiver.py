import socket, os, rsaClass
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# Obtain receiver and sender IP addresses
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ip_address = input("Enter IP address of receiver:\t")
sock.bind((ip_address, 5555))
sender_ip_address = input("Enter IP address of sender:\t")

# Generate public and private keys
rsa_class = rsaClass.rsaClass()
rsa_class.generate_keys()

# Send public key to sender
public_key = rsa_class.get_public_key()
sock.sendto(public_key, (sender_ip_address, 4444))
print(f"Public key sent to sender\nAwaiting encrypted message...\n\n")

# Wait for encrypted message
data = sock.recvfrom(1024)
print(f"Message received from {data[1]}")
print(f"Data Received:\t{data}\n")

# Decrypt encrypted message
decrypted_message = rsa_class.decrypt_message(data[0])
print(f"Decrypted:\t{decrypted_message}")
