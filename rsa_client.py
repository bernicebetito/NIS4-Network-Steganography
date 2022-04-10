import socket, os, rsaClass
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


rsa_class = rsaClass()
rsa_class.generate_keys()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ip_address = input("Enter IP address of server:\t")
sock.bind((ip_address, 12345))
sock.listen(5)
server_sock, sock_info = sock.accept()
data = server_sock.recv(1024)

print(f"Data Received:\t{data}\n\n")
