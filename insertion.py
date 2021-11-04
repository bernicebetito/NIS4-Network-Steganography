# Generation of key
from Crypto.Random import get_random_bytes
# Packet creation / manipulation
from scapy.all import IP
# Decode / Encode byte
import binascii
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
decoded = binascii.hexlify(key).decode()
payloadA = ''.join(format(ord(i), '08b') for i in decoded)
payloadB = hashlib.sha256(binascii.unhexlify(decoded))

start = 0
end = 16
divided_payload = []
while start < len(payloadA):
    extractor = ("0" * start) + ("1" * 16) + ("0" * (len(payloadA) - end))
    curr_payload = int(payloadA, 2) & int(extractor, 2)
    curr_payload = curr_payload >> len(payloadA) - end
    curr_payload = ("0" * (16 - len(format(curr_payload, 'b')))) + format(curr_payload, 'b')
    divided_payload.append(curr_payload)
    start += 16
    end += 16

print(*divided_payload, sep="\n")
print("\n")

reverse_payload = ""
for i in divided_payload:
    reverse_payload += i

extracted_payload = ""
for i in range(0, len(reverse_payload), 8):
    curr_char = reverse_payload[i:i + 8]
    extracted_payload = extracted_payload + chr(int(curr_char, 2))

print(payloadB.digest())
print(hashlib.sha256(binascii.unhexlify(extracted_payload)).digest())
