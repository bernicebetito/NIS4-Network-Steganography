# Generation of key
from Crypto.Random import get_random_bytes
# Packet creation / manipulation
from scapy.all import *
# Turn payload into byte
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

dns_ctr = 0
while (len(steganograms) != n):
    timestamp_option = IPOption(b'\x44')
    packet = IP(src=src_address, dst=dst_address, options=[
        timestamp_option, timestamp_option, timestamp_option,
        timestamp_option, timestamp_option
    ]) / UDP(dport=12345) / DNS(id=dns_ctr, qd=DNSQR(qname="www.google.com", qtype="A"))
    steganograms.append(packet)
    dns_ctr += 1


# ----------------------------------------
# Payload Insertion Module
# ----------------------------------------

# Turn payload into binary
payloadA = ''.join(format(i, '08b') for i in key)
payloadA = ("0" * (256 - len(payloadA))) + payloadA

print(payloadA)
print(len(payloadA))
print("\n\n")

# Get the hash value of the payload
payloadB = hashlib.sha256(key)
print(payloadB)
print(payloadB.digest())
print("\n\n")

# For extraction & key interpretation
insert_payload = []

# Divide and insert the payload into the steganogram packets
payload_ctr = 0
start = 0
end = 16
i = 0
N = len(steganograms)
while i != N and start < len(payloadA):
    ts_options = []

    steg_ctr = i
    steg_ctr = bin(steg_ctr)
    steg_ctr = steg_ctr[2:]
    steg_ctr = ("0" * (4 - len(steg_ctr))) + steg_ctr

    extractor = ("0" * start) + ("1" * 16) + ("0" * (len(payloadA) - end))
    curr_payload = int(payloadA, 2) & int(extractor, 2)
    curr_payload = curr_payload >> len(payloadA) - end
    curr_payload = ("0" * (16 - len(format(curr_payload, 'b')))) + format(curr_payload, 'b')

    for payload_ctr in range(-4, 16, 4):
        if payload_ctr < 0:
            ovflw_flg = hex(int((steg_ctr + "0000"), 2))
        else:
            payload_start = payload_ctr
            payload_end = payload_ctr + 4
            curr_char = curr_payload[payload_start:payload_end]
            insert_payload.append(curr_char)
            ovflw_flg = hex(int((curr_char + "0000"), 2))

        ovflw_flg = ovflw_flg[2:] + ("0" * (2 - len(ovflw_flg[2:])))
        insert_option = binascii.unhexlify(ovflw_flg)
        ts_options.append(IPOption(b'\x44\x04\x05' + insert_option))

    steganograms[i].options = ts_options

    payload_ctr += 4
    i += 1
    start += 16
    end += 16


# Print contents of steganogram packets
packet_count = 1
print("\n{:<51}\n".format("=" * 51))
for i in steganograms:
    print("\n{:<20} Packet {:<2} {:<20}\n".format(("x" * 20), packet_count, ("x" * 20)))
    print(i.show())
    packet_count += 1
    print("\n{:<51}\n".format("x" * 51))

print("\n{:<51}\n".format("=" * 51))


# --------------------- !!! NOT PART OF THE PROCESS !!! ---------------------
# This part is for extraction & key interpretation / checking if division was correct

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
            else:
                payload_ctr = True
    """
    for ctr in range(1, 5):
        temp_hex = binascii.hexlify(bytes(i.options[ctr])[3:])
        temp_bin = bin(int(temp_hex, 16))[2:]
        temp_bin = ("0" * (8 - len(temp_bin))) + temp_bin
        temp_bin = temp_bin[:4]
        test_extract += temp_bin
    """

# Compare the binary payload and the binary extracted
print(payloadA, end="\n\n")
print(test_extract)
print(payloadA == test_extract, end="\n\n")

# Turn the binary into bytes
extracted_payload = bytes(int(test_extract[i : i + 8], 2) for i in range(0, len(test_extract), 8))

# Compare the hash value of payload and extracted payload
print(payloadB.digest())
print(hashlib.sha256(extracted_payload).digest(), end="\n\n")

# Comparing the original key and extracted payload
print(key)
print(bytes(extracted_payload))

send(steganograms)