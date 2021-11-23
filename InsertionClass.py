# Generation of key
from Crypto.Random import get_random_bytes
# Packet creation / manipulation
from scapy.all import *
# Turn payload into byte
import binascii
# Hash equivalent of key
import hashlib

class InsertionClass (object):

    def getKey(self):
        # ----------------------------------------
        # Symmetric Key Generation Module
        # ----------------------------------------
        key = get_random_bytes(32)
        return key

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

        while (len(steganograms) != n):
            timestamp_option = IPOption(b'\x44')
            packet = IP(src=src_address, dst=dst_address, options=[
                timestamp_option, timestamp_option, timestamp_option,
                timestamp_option, timestamp_option
            ]) / UDP(dport=11234) / DNS(id=1, rd=1, qd=DNSQR(qname="www.google.com", qtype="A"))
            steganograms.append(packet)

        return steganograms

    def insertPayload(self, key, steganograms):
        # ----------------------------------------
        # Payload Insertion Module
        # ----------------------------------------

        # Turn payload into binary
        payloadA = ''.join(format(i, '08b') for i in key)
        payloadA = ("0" * (256 - len(payloadA))) + payloadA

        # Get the hash value of the payload
        payloadB = hashlib.sha256(key)

        # For extraction & key interpretation
        insert_payload = []

        # Divide and insert the payload into the steganogram packets
        timestamp_ctr = 0
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

            timestamp_ctr += 4
            i += 1
            start += 16
            end += 16
        
        return steganograms, payloadB

    def getSteganograms(self, src_address, dst_address):
        key = self.getKey()
        empty_steganograms = self.prepareSteganograms(src_address, dst_address)
        steganograms, hash = self.insertPayload(key, empty_steganograms)

        return steganograms, hash
