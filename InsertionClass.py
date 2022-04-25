# Generation of key
from Crypto.Random import get_random_bytes
# Packet creation / manipulation
from scapy.all import *
# Turn payload into byte
import binascii
# Hash equivalent of key
import hashlib
# DNS Types, DNS Domains, Dummy Packets
import random


class InsertionClass (object):

    def __init__(self):
        self.dns_types = ["A", "NS", "MD", "MF",
                          "CNAME", "SOA", "MB", "MG",
                          "MR", "NULL", "WKS", "PTR",
                          "HINFO", "MINFO", "MX", "TXT",
                          "AXFR", "MAILB", "MAILA", "ANY"]

    def getKey(self):
        # ----------------------------------------
        # Symmetric Key Generation Module
        # ----------------------------------------
        key = get_random_bytes(32)
        return key

    def getXORKey(self):
        xor_key = b"M\x80Q\xa7\x0b\x0c'h\x80\xc5\x9d@\xa1\xb2\xb8>?hl\xf6\xed7}\xb7\xbfQw\x06H\x93\xe5\xc3"
        return xor_key

    def prepareSteganograms(self, src_address, dst_address):
        # ----------------------------------------
        # Steganogram Preparation Module
        # ----------------------------------------
        size_payload = 256
        num_bits = 16
        n = size_payload / num_bits
        steganograms = []
        src_address = src_address
        dst_address = dst_address

        dns_ctr = 0
        steg_websites = [
            "www.macys.com",
            "www.imdb.com",
            "www.allrecipes.com",
            "www.walgreens.com",
            "www.cheatsheet.com",

            "www.instagram.com",
            "www.wikipedia.org",
            "www.twitch.tv",
            "www.imgur.com",
            "www.quora.com"
        ]

        while (len(steganograms) != n):
            timestamp_option = IPOption(b'\x44')
            packet = IP(src=src_address, dst=dst_address, options=[
                timestamp_option, timestamp_option, timestamp_option,
                timestamp_option, timestamp_option
            ]) / UDP(dport=11234) / DNS(id=dns_ctr, qd=DNSQR(qname=random.choice(steg_websites), qtype=random.choice(self.dns_types)))
            steganograms.append(packet)
            dns_ctr += 1

        return steganograms

    def payloadInsertion(self, key, xor_key, steganograms, src_address, dst_address):
        # ----------------------------------------
        # Payload Insertion Module
        # ----------------------------------------

        # Get the hash value of the payload
        payloadB = hashlib.sha256(key)

        # Perform XOR operation on key and turn into binary
        xored_key = bytes([a ^ b for a, b in zip(key, xor_key)])
        payloadA = ''.join(format(i, '08b') for i in xored_key)
        payloadA = ("0" * (256 - len(payloadA))) + payloadA

        payload_ctr = 0
        start = 0
        end = 16
        i = 0
        N = len(steganograms)

        # Divide and insert the payload into the steganogram packets
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
        #random.shuffle(steganograms)

        # Add the dummy packets between steganograms
        index_dummy = []
        start_dummy = 0
        end_dummy = 2
        while end_dummy <= 16:
            curr_index = random.randint(start_dummy, end_dummy)
            index_dummy.append(curr_index)
            start_dummy = curr_index + 1
            end_dummy = start_dummy + 2

        rand_websites = [
            "www.accuweather.com",
            "www.costco.com",
            "www.homedepot.com",
            "www.webmd.com",
            "www.outbrain.com",

            "www.lowes.com",
            "www.kohls.com",
            "www.office.com",
            "www.blogspot.com",
            "www.betsbuy.com"
        ]

        for i in range(len(index_dummy)):
            dummy_timestamp = []
            for timestamp_ctr in range(5):
                ovflw_flg = hex(int((bin(random.randint(0, 15))[2:] + "0000"), 2))
                ovflw_flg = ovflw_flg[2:] + ("0" * (2 - len(ovflw_flg[2:])))
                insert_option = binascii.unhexlify(ovflw_flg)
                dummy_timestamp.append(IPOption(b'\x44\x04\x05' + insert_option))

            packet = IP(src=src_address, dst=dst_address, options=dummy_timestamp) / UDP(dport=11234) / DNS(id=i, qd=DNSQR(qname=random.choice(rand_websites), qtype=random.choice(self.dns_types)))
            steganograms.insert(index_dummy[i] + i, packet)

        return steganograms, payloadB

    def getSteganograms(self, src_address, dst_address, xor_key):
        key = self.getKey()
        empty_steganograms = self.prepareSteganograms(src_address, dst_address)
        self.steganograms, hash = self.payloadInsertion(key, xor_key, empty_steganograms, src_address, dst_address)

        return self.steganograms[:10], hash

    # Retrieves the missing steganogram.
    # steg_ctr = int => Steganogram Counter
    def findSteganogram(self, steg_indexes):
        steg_websites = [
            "www.macys.com",
            "www.imdb.com",
            "www.allrecipes.com",
            "www.walgreens.com",
            "www.cheatsheet.com",

            "www.instagram.com",
            "www.wikipedia.org",
            "www.twitch.tv",
            "www.imgur.com",
            "www.quora.com"
        ]
        missing_steganograms = []
        for i in self.steganograms:
            if i[DNS].qd.qname.decode() in steg_websites:
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

                            if curr_ctr in steg_indexes:
                                missing_steganograms.append(i)
            else:
                missing_steganograms.append(i)
        return missing_steganograms