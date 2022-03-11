# Generation of key
from Crypto.Random import get_random_bytes
# Packet creation / manipulation
from scapy.all import *
# Turn payload into byte
import binascii
# Hash equivalent of key
import hashlib
# Dummy Packets
import random

# ----------------------------------------
# Symmetric Key Generation Module
# ----------------------------------------
key = get_random_bytes(32)
print("Key: ", key, "\n", len(key), " Bytes", end="\n\n")

xor_key = get_random_bytes(32)
print("XOR Key: ", xor_key, "\n", len(xor_key), " Bytes", end="\n\n")


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
dns_types = ["A", "NS", "MD", "MF",
             "CNAME", "SOA", "MB", "MG",
             "MR", "NULL", "WKS", "PTR",
             "HINFO", "MINFO", "MX", "TXT",
             "AXFR", "MAILB",  "MAILA", "ANY"]

while (len(steganograms) != n):
    timestamp_option = IPOption(b'\x44')
    packet = IP(src=src_address, dst=dst_address, options=[
        timestamp_option, timestamp_option, timestamp_option,
        timestamp_option, timestamp_option
    ]) / UDP(dport=12345) / DNS(id=dns_ctr, qd=DNSQR(qname="www.google.com", qtype=random.choice(dns_types)))
    steganograms.append(packet)
    dns_ctr += 1

# ----------------------------------------
# Payload Insertion Module
# ----------------------------------------

# Turn payload into binary
xored_key = bytes([a ^ b for a, b in zip(key, xor_key)])
payloadA = ''.join(format(i, '08b') for i in xored_key)
payloadA = ("0" * (256 - len(payloadA))) + payloadA

print(payloadA)
print(len(payloadA))
print("\n\n")

# Get the hash value of the payload
payloadB = hashlib.sha256(key)
print(payloadB)
print(payloadB.digest())
print("\n\n")

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
            ovflw_flg = hex(int((curr_char + "0000"), 2))

        ovflw_flg = ovflw_flg[2:] + ("0" * (2 - len(ovflw_flg[2:])))
        insert_option = binascii.unhexlify(ovflw_flg)
        ts_options.append(IPOption(b'\x44\x04\x05' + insert_option))

    steganograms[i].options = ts_options

    payload_ctr += 4
    i += 1
    start += 16
    end += 16

# Shuffle steganograms, for testing the sorting portion
random.shuffle(steganograms)

# Insertion of dummy packets
curr_index = 0
num_steg = len(steganograms)
for curr_steg in range(num_steg):
    curr_index += 1
    num_packets = random.randint(1, 3)
    dummy_timestamp = []
    for j in range(num_packets):
        for timestamp_ctr in range(5):
            ovflw_flg = hex(int((bin(random.randint(0, 15))[2:] + "0000"), 2))
            ovflw_flg = ovflw_flg[2:] + ("0" * (2 - len(ovflw_flg[2:])))
            insert_option = binascii.unhexlify(ovflw_flg)
            dummy_timestamp.append(IPOption(b'\x44\x04\x05' + insert_option))

        packet = IP(src=src_address, dst=dst_address, options=dummy_timestamp) / UDP(dport=12345) / DNS(id=random.randint(0, 15),
                 qd=DNSQR(qname="www.goog1e.com", qtype=random.choice(dns_types)))
        steganograms.insert(curr_index + j, packet)
    print("index: ", curr_index, "packets: ", num_packets, end="\n\n")
    curr_index += num_packets

# Print Payload Hash
print("\n\n", end="Payload Hash: ")
print(payloadB.digest(), end="\n\n")
# """
# Print contents of steganogram packets
packet_count = 1
print("\n{:<51}\n".format("=" * 51))
for i in steganograms:
    print("\n{:<20} Packet {:<2} {:<20}\n".format(("x" * 20), packet_count, ("x" * 20)))
    print(i.show())
    packet_count += 1
    print("\n{:<51}\n".format("x" * 51))

print("\n{:<51}\n".format("=" * 51))
# """
# ------------------------- !!! NOT PART OF THE PROCESS !!! -------------------------
# This part is for extraction & key interpretation
"""
GUIDE
"Actual steganogram" => steganograms that contain the symmetric key

missing_indexes =>  list which contains the counter of the actual steganogram to be removed / deemed missing
                => [0, 1, 2]

missing_steganograms    => list which contains all the steganograms except for the "missing" ones
                        => [steganogram]

extracted   => list which contains the actual steganograms and their counter
            => [[actual_steg, counter]]

sorted_steganograms => list which contains the actual steganograms
                    => [actual_steg]

sorted_indexes  => list which contains all the counters of the retrieved actual steganograms
                => [0, 1, 2]
"""

# To test missing steganograms
missing_steganograms = []

# Get random indexes of actual steganograms to remove
missing_indexes = []
for x in range(5):
    temp_index = random.randint(0, 15)
    while temp_index in missing_indexes:
        temp_index = random.randint(0, 15)
    missing_indexes.append(temp_index)

# Append steganograms to the missing_steganograms list except for the
# actual ones with an index which is in the missing_indexes list
for i in steganograms:
    if "google" in i[DNS].qd.qname.decode():
        temp_bytes = binascii.hexlify(bytes(i))
        payload_ctr = False
        for ctr in range(0, len(temp_bytes) - 2, 2):
            check_byte = temp_bytes[ctr:ctr+2]
            if check_byte == b'44' and temp_bytes[ctr+2:ctr+4] == b'04':
                if not payload_ctr:
                    temp_hex = temp_bytes[ctr + 6:ctr + 8]
                    temp_bin = bin(int(temp_hex, 16))[2:]
                    temp_bin = ("0" * (8 - len(temp_bin))) + temp_bin
                    temp_bin = temp_bin[:4]
                    curr_steg = int(temp_bin, 2)
                    payload_ctr = True

                    if curr_steg not in missing_indexes:
                        missing_steganograms.append(i)
    else:
        missing_steganograms.append(i)

# Extract the counter of each steganogram
extracted = []
for i in missing_steganograms:
    if "google" in i[DNS].qd.qname.decode():
        temp_bytes = binascii.hexlify(bytes(i))
        payload_ctr = False
        for ctr in range(0, len(temp_bytes) - 2, 2):
            check_byte = temp_bytes[ctr:ctr+2]
            if check_byte == b'44' and temp_bytes[ctr+2:ctr+4] == b'04':
                # This if not statement means the payload counter hasn't been found yet
                if not payload_ctr:
                    # Extracting and conversion to integer
                    temp_hex = temp_bytes[ctr + 6:ctr + 8]
                    temp_bin = bin(int(temp_hex, 16))[2:]
                    temp_bin = ("0" * (8 - len(temp_bin))) + temp_bin
                    temp_bin = temp_bin[:4]
                    curr_steg = int(temp_bin, 2)

                    # Append counter and the whole steganogram
                    extracted.append([curr_steg, i])
                    payload_ctr = True


# This function simulates a call to findSteganogram found in the InsertionClass
# It returns the missing steganogram if found
def getMissingSteg(steg_num):
    for i in steganograms:
        if "google" in i[DNS].qd.qname.decode():
            temp_bytes = binascii.hexlify(bytes(i))
            payload_ctr = False
            for ctr in range(0, len(temp_bytes) - 2, 2):
                check_byte = temp_bytes[ctr:ctr + 2]
                if check_byte == b'44' and temp_bytes[ctr + 2:ctr + 4] == b'04':
                    if not payload_ctr:
                        temp_hex = temp_bytes[ctr + 6:ctr + 8]
                        temp_bin = bin(int(temp_hex, 16))[2:]
                        temp_bin = ("0" * (8 - len(temp_bin))) + temp_bin
                        temp_bin = temp_bin[:4]
                        curr_ctr = int(temp_bin, 2)
                        payload_ctr = True

                        if curr_ctr == steg_num:
                            return i


# Sort the packet then append the packets to a new list
extracted.sort()
sorted_steganograms = []
sorted_indexes = []

# Append the steganogram and counter to their respective list
for x in extracted:
    sorted_steganograms.append(x[1])
    sorted_indexes.append(x[0])

# List comprehension to retrieve the missing indexes
"""
What happens is the for loop iterates through 0 to 16 and if the current number (steg_ctr) isn't
in the sorted_indexes list, append the current number (steg_ctr) to the extracted_indexes list
"""
extracted_indexes = [steg_ctr for steg_ctr in range(0, 16) if steg_ctr not in sorted_indexes]

print("\n\n")
print(missing_indexes)
print(extracted_indexes)

# Retrieve the missing steganograms by looping through the extracted_indexes list and calling
# getMissingSteg() for each element in the list
for x in extracted_indexes:
    missing_steg = getMissingSteg(x)
    if "google" in missing_steg[DNS].qd.qname.decode():
        temp_bytes = binascii.hexlify(bytes(missing_steg))
        payload_ctr = False
        for ctr in range(0, len(temp_bytes) - 2, 2):
            check_byte = temp_bytes[ctr:ctr + 2]
            if check_byte == b'44' and temp_bytes[ctr + 2:ctr + 4] == b'04':
                if not payload_ctr:
                    temp_hex = temp_bytes[ctr + 6:ctr + 8]
                    temp_bin = bin(int(temp_hex, 16))[2:]
                    temp_bin = ("0" * (8 - len(temp_bin))) + temp_bin
                    temp_bin = temp_bin[:4]
                    curr_steg = int(temp_bin, 2)
                    payload_ctr = True

                    if curr_steg == x:
                        sorted_steganograms.insert(x, missing_steg)

print("\n\n")
test_extract = ""
for i in sorted_steganograms:
    if "google" in i[DNS].qd.qname.decode():
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
print(bytes(extracted_payload), end="\n\n")

extracted_payload = bytes([a ^ b for a, b in zip(xor_key, extracted_payload)])
print(key)
print(xor_key)
print(extracted_payload)


# send(steganograms)