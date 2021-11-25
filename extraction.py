# Packet creation / manipulation
from scapy.all import *
# Turn payload into byte
import binascii
# Hash equivalent of key
import hashlib


test_extract = ""
for i in steganograms:
  print (i.options[0].oflw)
  
  for ctr in range(1,5)
  temp_hex = binascii.hexlify(bytes(i.options[ctr])[3:])
  temp_bin = bin(int(temp_hex,16))[2:]
  temp_bin = ("0" * (8 - len(temp_bin))) + temp_bin
  temp_bin = temp_bin[4:]
  test_extract += temp_bin

# Turn binary payload into bytes
for i in range(0, len(test_extract)):
    temp = chr(int(test_extract[i], 2))
    test_extract[i] = temp.encode()

# Decode the payload
decode_payload = ""
for i in test_extract:
    decode_payload += i.decode()

# Turn the decoded payload into binary
bin_payload = ''.join(format(ord(i), '04b') for i in decode_payload)

# Compare the binary payload and the binary extracted
print(payloadA, end="\n\n")
print(bin_payload, end="\n\n")
print("Checker:" + payloadA == bin_payload)

# Turn the binary into bytes
extracted_payload = bytes(int(bin_payload[i : i + 8], 2) for i in range(0, len(bin_payload), 8))

# Compare the hash value of payload and extracted payload
print(payloadB.digest())
print(hashlib.sha256(extracted_payload).digest(), end="\n\n")
print("Checker:" + payloadB.digest() == hashlib.sha256(extracted_payload.digest(),end="\n\n")

# Comparing the original key and extracted payload
print(key)
print(bytes(extracted_payload))
print("Checker:" + key == bytes(extracted_payload))

ans, unans = sr(steganograms, retry=0, timeout=5)
