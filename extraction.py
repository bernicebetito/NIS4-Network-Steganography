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
  temp_bin = temp_bin[:4]
  test_extract += temp_bin

# Compare the binary payload and the binary extracted
print(payloadA, end="\n\n")
print(test_extract, end="\n\n")
str_1 = str(payloadA)
str_2 = str(test_extract)
print("Checker:" + str_1 == str_2,end="\n\n")

# Turn the binary into bytes
extracted_payload = bytes(int(test_extract[i : i + 8], 2) for i in range(0, len(test_extract), 8))

# Compare the hash value of payload and extracted payload
print(payloadB.digest())
print(hashlib.sha256(extracted_payload).digest(), end="\n\n")
str_3 = str(payloadB.digest())
str_4 = str(hashlib.sha256(extracted_payload).digest())
print("Checker:" + atr_3 == str_4,end="\n\n")

# Comparing the original key and extracted payload
print(key)
print(bytes(extracted_payload))
str_5 = str(key)
str_6 = str(bytes(extracted_payload))
print("Checker:" + str_5 == str_6))

ans, unans = sr(steganograms, retry=0, timeout=5)
