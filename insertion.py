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
size_payload = 256
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
    ]) / DNS(qd=DNSQR(qname="www.google.com"))
    steganograms.append(packet)


# ----------------------------------------
# Payload Insertion Module
# ----------------------------------------
payloadA = ''.join(format(i, '08b') for i in key)
payloadA = ("0" * (256 - len(payloadA))) + payloadA
payloadB = hashlib.sha256(key)
print(payloadA)
print(len(payloadA))
print("\n\n")

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
        insert_payload.append(curr_char)

    start += 16
    end += 16


timestamp_ctr = 0
i = 0
N = len(steganograms)

while i != N:
    ts_options = []

    steg_ctr = i
    steg_ctr = bin(steg_ctr)
    steg_ctr = steg_ctr[2:]
    steg_ctr = ("0" * (4 - len(steg_ctr))) + steg_ctr

    for curr_option in range(-1, 4):
        if curr_option < 0:
            ovflw_flg = hex(int((steg_ctr + "0000"), 2))
        else:
            ovflw_flg = hex(int((insert_payload[curr_option + timestamp_ctr] + "0000"), 2))
        ovflw_flg = ovflw_flg[2:] + ("0" * (2 - len(ovflw_flg[2:])))
        insert_option = binascii.unhexlify(ovflw_flg)
        ts_options.append(IPOption(b'\x44\x04\x05' + insert_option))

    steganograms[i].options = ts_options

    timestamp_ctr += 4
    i += 1


for i in steganograms:
    print(i.show())
    print("\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n")


for i in range(0, len(insert_payload)):
    temp = chr(int(insert_payload[i], 2))
    insert_payload[i] = temp.encode()


decode_payload = ""
for i in insert_payload:
    decode_payload += i.decode()

bin_payload = ''.join(format(ord(i), '04b') for i in decode_payload)
extracted_payload = ""
for i in range(0, len(bin_payload), 8):
    curr_char = bin_payload[i:i + 8]
    extracted_payload += chr(int(curr_char, 2))

print(payloadB.digest())
print(hashlib.sha256(bytes(int(bin_payload[i : i + 8], 2) for i in range(0, len(bin_payload), 8))).digest())

print("\n\n")
print(key)
print(bytes(int(bin_payload[i : i + 8], 2) for i in range(0, len(bin_payload), 8)))