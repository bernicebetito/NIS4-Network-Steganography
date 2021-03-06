# Packet creation / manipulation
from scapy.all import *
# Turn payload into byte
import binascii
# Hash equivalent of key
import hashlib

test_extract = ""
for i in steganograms:
    temp_bytes = binascii.hexlify(bytes(i))
    payload_ctr = False
    for ctr in range(0, len(temp_bytes) - 2, 2):
        check_byte = temp_bytes[ctr:ctr+2]
        if check_byte == b'44' and temp_bytes[ctr+2:ctr+4] == b'04':
            if payload_ctr:
                temp_hex = temp_bytes[ctr + 6:ctr + 8]
                temp_bin = bin(int(temp_hex, 16))[2:]
                temp_bin = ("0" * (8 - len(temp_bin))) + temp_bin
                temp_bin = temp_bin[:4]
                test_extract += temp_bin
                print(temp_bin)
            else:
                payload_ctr = True

# Compare the binary payload and the binary extracted
print(payloadA, end="\n\n")
print(test_extract, end="\n\n")
print("Checker:" + payloadA == test_extract, end="\n\n")

# Turn the binary into bytes
extracted_payload = bytes(int(test_extract[i : i + 8], 2) for i in range(0, len(test_extract), 8))

# Compare the hash value of payload and extracted payload
print(payloadB.digest())
print(hashlib.sha256(extracted_payload).digest(), end="\n\n")
print("Checker:", payloadB.digest() == hashlib.sha256(extracted_payload).digest(), end="\n\n")

# Comparing the original key and extracted payload
print(key)
print(bytes(extracted_payload))
print("Checker:", key == bytes(extracted_payload))
