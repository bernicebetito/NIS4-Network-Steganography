import socket, os, rsaClass, psutil, time
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

testing_results = []

rsa_class = rsaClass.rsaClass()
#rsa_class.generate_keys()

# Obtain sender and receiver IP addresses
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ip_address = input("Enter IP address of sender:\t")
sock.bind((ip_address, 4444))
receiver_ip_address = input("Enter IP address of receiver:\t")

# Obtain public key
print("\n\nWaiting for public key...")
data = sock.recvfrom(1024)
start_time = time.time()
print(f"Public key received from {data[1]}")

testing_results.append(f'CPU usage before encryption - {psutil.cpu_percent()}')

#  Generate random message, encrypt and send 
message = get_random_bytes(32)
encrypted_message = rsa_class.encrypt(message, data[0])
sock.sendto(encrypted_message, (receiver_ip_address, 5555))
print("Encrypted message sent\n\n")

testing_results.append(f'CPU usage after encryption - {psutil.cpu_percent()}')

end_time = time.time() - start_time
testing_results.append(f'Program elapsed time - {end_time} seconds')

# For Testing / Comparing
decrypted_message = rsa_class.decrypt_message(encrypted_message)
print(f"Message:\t{message}\n")
print(f"Encrypted:\t{encrypted_message}\n")
print(f"Decrypted:\t{decrypted_message}")

for result in testing_results:
    print(result)
