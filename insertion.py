# Generation of key
from Crypto.Random import get_random_bytes
# Packet creation / manipulation
from scapy.all import IP
# Decode byte
from base64 import b64encode
# Hash equivalent of key
import hashlib

# ----------------------------------------
# Symmetric Key Generation Module
# ----------------------------------------
key = get_random_bytes(32)
print(key)


# ----------------------------------------
# Steganogram Preparation Module
# ----------------------------------------
size_payload = 256
num_bits = 16
n = size_payload / num_bits
steganograms = []
src_address = "192.168.254.108"
dst_address = "192.168.254.132"

while (len(steganograms) != n):
    packet = IP(src=src_address, dst=dst_address)
    steganograms.append(packet)

for i in steganograms:
    print(i.show())
    print("\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n")


# ----------------------------------------
# Payload Insertion Module
# ----------------------------------------
decoded = b64encode(key).decode()
payloadA = ''.join(format(ord(i), '08b') for i in decoded)
payloadB = hashlib.sha256(key)