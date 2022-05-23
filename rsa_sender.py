from ipaddress import ip_address
import socket, os, rsaClass, psutil, time
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

testing_results = []

rsa_class = rsaClass.rsaClass()
#rsa_class.generate_keys()

# Obtain sender and receiver IP addresses
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#ip_address = input("Enter IP address of sender:\t")
ip_address = "192.168.1.30"
sock.bind((ip_address, 4444))
#receiver_ip_address = input("Enter IP address of receiver:\t")
receiver_ip_address = "192.168.1.29"

# Obtain public key
print("\n\nWaiting for public key...")
data = sock.recvfrom(1024)
#os.popen("python3 data_collection.py")
start_time = time.time()
print(f"Public key received from {data[1]}")

#testing_results.append(f'CPU usage before encryption - {psutil.cpu_percent()}')

#  Generate random message, encrypt and send 
message = get_random_bytes(32)
start_enc_time = time.time()
encrypted_message = rsa_class.encrypt(message, data[0])
end_enc_time = time.time() - start_enc_time
sock.sendto(encrypted_message, (receiver_ip_address, 5555))
print("Encrypted message sent\n\n")

#testing_results.append(f'CPU usage after encryption - {psutil.cpu_percent()}')

end_time = time.time() - start_time
testing_results.append(f'Program elapsed time - {end_time} seconds')

# For Testing / Comparing
#decrypted_message = rsa_class.decrypt_message(encrypted_message)
print(f"Message:\t{message}\n")
print(f"Encrypted:\t{encrypted_message}\n")
#print(f"Decrypted:\t{decrypted_message}")

print(f'Time taken to encrypt message {end_enc_time} seconds')

for result in testing_results:
    print(result)
