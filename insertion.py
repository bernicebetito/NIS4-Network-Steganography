# Generation of key
from Crypto.Random import get_random_bytes
# Packet creation / manipulation
from scapy.all import *
# Decode / Encode byte
import binascii
# Hash equivalent of key
import hashlib

# ----------------------------------------
# Symmetric Key Generation Module
# ----------------------------------------
key = get_random_bytes(32)
print(key, end="\n\n")


# ----------------------------------------
# Steganogram Preparation Module
# ----------------------------------------
size_payload = 512
num_bits = 16
n = size_payload / num_bits
steganograms = []
src_address = "192.168.254.108"
dst_address = "192.168.254.132"

while (len(steganograms) != n):
    timestamp_option = IPOption(b'\x44')
    packet = IP(src=src_address, dst=dst_address, options=[
        timestamp_option, timestamp_option, timestamp_option,
        timestamp_option, timestamp_option
    ])
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
insert_payload = []
while start < len(payloadA):
    extractor = ("0" * start) + ("1" * 16) + ("0" * (len(payloadA) - end))
    curr_payload = int(payloadA, 2) & int(extractor, 2)
    curr_payload = curr_payload >> len(payloadA) - end
    curr_payload = ("0" * (16 - len(format(curr_payload, 'b')))) + format(curr_payload, 'b')

    for i in range(0, 16, 4):
        payload_start = i
        payload_end = i + 4
        curr_char = curr_payload[payload_start:payload_end]
        curr_char = chr(int(curr_char, 2))
        insert_payload.append(curr_char.encode())

    start += 16
    end += 16

print(*insert_payload, sep="\n")
print("\n")


timestamp_1 = 0
timestamp_2 = 1
timestamp_3 = 2
timestamp_4 = 3
for i in range(0, len(steganograms)):
    """
    steg_ctr = str(i + 1)
    steg_ctr = chr(int(steg_ctr, 2))
    print("\n\n=======================================================\n")
    print(steg_ctr)
    print("\n=======================================================\n\n")
    """

    insert_1 = b'01' + insert_payload[timestamp_1] + b'10'
    insert_2 = b'01' + insert_payload[timestamp_2] + b'10'
    insert_3 = b'01' + insert_payload[timestamp_3] + b'10'
    insert_4 = b'01' + insert_payload[timestamp_4] + b'10'
    payload_timestamp_1 = IPOption(b'\x44\x04\x05' + insert_1)
    payload_timestamp_2 = IPOption(b'\x44\x04\x05' + insert_2)
    payload_timestamp_3 = IPOption(b'\x44\x04\x05' + insert_3)
    payload_timestamp_4 = IPOption(b'\x44\x04\x05' + insert_4)
    steganograms[i].options = [
        payload_timestamp_1, payload_timestamp_2,
        payload_timestamp_3, payload_timestamp_4
    ]

    timestamp_1 += 4
    timestamp_2 += 4
    timestamp_3 += 4
    timestamp_4 += 4


for i in steganograms:
    print(i.show())
    print("\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n")


decode_payload = ""
for i in insert_payload:
    decode_payload += i.decode()

bin_payload = ''.join(format(ord(i), '04b') for i in decode_payload)
extracted_payload = ""
for i in range(0, len(bin_payload), 8):
    curr_char = bin_payload[i:i + 8]
    extracted_payload += chr(int(curr_char, 2))

print(payloadB.digest())
print(hashlib.sha256(binascii.unhexlify(extracted_payload)).digest())