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
        xor_key = get_random_bytes(32)
        return key, xor_key

    def prepareSteganograms(self, qdomain, src_address, dst_address):
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
        while (len(steganograms) != n):
            timestamp_option = IPOption(b'\x44')
            packet = IP(src=src_address, dst=dst_address, options=[
                timestamp_option, timestamp_option, timestamp_option,
                timestamp_option, timestamp_option
            ]) / UDP(dport=11234) / DNS(id=dns_ctr, qd=DNSQR(qname=qdomain, qtype="A"))
            steganograms.append(packet)
            dns_ctr += 1

        return steganograms

    def payloadInsertion(self, key, xor_key, steganograms, xor_steganograms):
        # ----------------------------------------
        # Payload Insertion Module
        # ----------------------------------------

        # Turn payload into binary
        xored_key = bytes([a ^ b for a, b in zip(key, xor_key)])
        payloadA = ''.join(format(i, '08b') for i in xored_key)
        payloadA = ("0" * (256 - len(payloadA))) + payloadA

        xor_payload = ''.join(format(i, '08b') for i in xor_key)
        xor_payload = ("0" * (256 - len(xor_payload))) + xor_payload

        # Get the hash value of the payload
        payloadB = hashlib.sha256(key)

        # Insert payload into steganograms
        steganograms = self.insertPayload(steganograms, payloadA)
        xor_steganograms = self.insertPayload(xor_steganograms, xor_payload)

        # Add dummy packets between steganograms
        steganograms = self.addDummy(steganograms)

        # Combine all steganograms into one list
        steganograms = xor_steganograms + steganograms

        return steganograms, payloadB

    def insertPayload(self, packetList, payload):
        payload_ctr = 0
        start = 0
        end = 16
        i = 0
        N = len(packetList)

        # Divide and insert the payload into the steganogram packets
        while i != N and start < len(payload):
            ts_options = []

            steg_ctr = i
            steg_ctr = bin(steg_ctr)
            steg_ctr = steg_ctr[2:]
            steg_ctr = ("0" * (4 - len(steg_ctr))) + steg_ctr

            extractor = ("0" * start) + ("1" * 16) + ("0" * (len(payload) - end))
            curr_payload = int(payload, 2) & int(extractor, 2)
            curr_payload = curr_payload >> len(payload) - end
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

            packetList[i].options = ts_options

            payload_ctr += 4
            i += 1
            start += 16
            end += 16

        return packetList

    def addDummy(self, steganograms):
        index_dummy = []
        start_dummy = 0
        end_dummy = 2
        while end_dummy <= 16:
            curr_index = random.randint(start_dummy, end_dummy)
            index_dummy.append(curr_index)
            start_dummy = curr_index + 1
            end_dummy = start_dummy + 2

        for i in range(len(index_dummy)):
            dummy_timestamp = []
            for timestamp_ctr in range(5):
                ovflw_flg = hex(int((bin(random.randint(0, 15))[2:] + "0000"), 2))
                ovflw_flg = ovflw_flg[2:] + ("0" * (2 - len(ovflw_flg[2:])))
                insert_option = binascii.unhexlify(ovflw_flg)
                dummy_timestamp.append(IPOption(b'\x44\x04\x05' + insert_option))

            packet = IP(src=src_address, dst=dst_address, options=dummy_timestamp) / UDP(dport=12345) / DNS(id=i, qd=DNSQR(qname="www.goog1e.com", qtype="A"))
            steganograms.insert(index_dummy[i] + i, packet)

    def getSteganograms(self, src_address, dst_address):
        key, xor_key = self.getKey()
        empty_steganograms = self.prepareSteganograms("www.google.com", src_address, dst_address)
        empty_xor_steganograms = self.prepareSteganograms("www.g0ogle.com", src_address, dst_address)
        steganograms, hash = self.payloadInsertion(key, xor_key, empty_steganograms, empty_xor_steganograms)

        return steganograms, hash
