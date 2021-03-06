# Packet creation / manipulation
from scapy.all import *
# Turn payload into byte
import binascii
# Hash equivalent of key
import hashlib


class extractionClass(object):

    def __init__(self):
        self.steg_websites = [
            "www.macys.com.",
            "www.imdb.com.",
            "www.allrecipes.com.",
            "www.walgreens.com.",
            "www.cheatsheet.com.",

            "www.instagram.com.",
            "www.wikipedia.org.",
            "www.twitch.tv.",
            "www.imgur.com.",
            "www.quora.com."
        ]
        self.sorted_indexes = []

    def extractKey(self, steganograms):
        # ----------------------------------------
        # Payload Extraction Module
        # ----------------------------------------

        # Extract the counter of each steganogram
        extractedKey = []
        for i in steganograms:
            if i[DNS].qd.qname.decode() in self.steg_websites:
                temp_bytes = binascii.hexlify(bytes(i))
                payload_ctr = False
                for ctr in range(0, len(temp_bytes) - 2, 2):
                    check_byte = temp_bytes[ctr:ctr + 2]
                    if check_byte == b'44' and temp_bytes[ctr + 2:ctr + 4] == b'04':
                        # If the payload counter hasn't been found yet
                        if not payload_ctr:
                            # Extracting and conversion to integer
                            temp_hex = temp_bytes[ctr + 6:ctr + 8]
                            temp_bin = bin(int(temp_hex, 16))[2:]
                            temp_bin = ("0" * (8 - len(temp_bin))) + temp_bin
                            temp_bin = temp_bin[:4]
                            curr_steg = int(temp_bin, 2)

                            # Append counter and the whole steganogram
                            if curr_steg not in self.sorted_indexes:
                                extractedKey.append([curr_steg, i])
                            payload_ctr = True

        # Sort then append the packets to a new list
        extractedKey.sort()
        self.extracted = [n for n in extractedKey if n[1] not in self.sorted_indexes]
        self.extracted.sort()

    def getMissingIndexes(self):
        # ----------------------------------------
        # Payload Extraction Module
        # ----------------------------------------

        self.sorted_indexes = []
        self.sorted_steganograms = []

        # Append the steganogram and counter to their respective list
        for x in self.extracted:
            self.sorted_steganograms.append(x[1])
            self.sorted_indexes.append(x[0])
        self.extracted_indexes = [steg_ctr for steg_ctr in range(0, 16) if steg_ctr not in self.sorted_indexes]
        print("Sorted indexes:\t", self.sorted_indexes)

        return self.extracted_indexes

    def insertMissing(self, missing_steganograms):
        # ----------------------------------------
        # Payload Extraction Module
        # ----------------------------------------

        extractedKey = self.extracted
        for x in missing_steganograms:
            if x[DNS].qd.qname.decode() in self.steg_websites:
                temp_bytes = binascii.hexlify(bytes(x))
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

                            if curr_steg in self.extracted_indexes and curr_steg not in self.sorted_indexes:
                                self.sorted_indexes.append(curr_steg)
                                extractedKey.append([curr_steg, x])
        extractedKey.sort()
        self.sorted_indexes.sort()
        self.extracted = [n for n in extractedKey if n[1] not in self.sorted_indexes]
        self.extracted.sort()

    def formKey(self):
        # ----------------------------------------
        # Payload Extraction Module
        # ----------------------------------------

        self.key = ""
        for i in self.sorted_steganograms:
            if i[DNS].qd.qname.decode() in self.steg_websites:
                temp_bytes = binascii.hexlify(bytes(i))
                payload_ctr = False
                for ctr in range(0, len(temp_bytes) - 2, 2):
                    check_byte = temp_bytes[ctr:ctr + 2]
                    if check_byte == b'44' and temp_bytes[ctr + 2:ctr + 4] == b'04':
                        if payload_ctr:
                            temp_hex = temp_bytes[ctr + 6:ctr + 8]
                            temp_bin = bin(int(temp_hex, 16))[2:]
                            temp_bin = ("0" * (8 - len(temp_bin))) + temp_bin
                            temp_bin = temp_bin[:4]
                            self.key += temp_bin
                        else:
                            payload_ctr = True

    def interpretKey(self):
        # ----------------------------------------
        # Key Interpretation Module
        # ----------------------------------------

        # Turn the binary into bytes
        xor_key = b"M\x80Q\xa7\x0b\x0c'h\x80\xc5\x9d@\xa1\xb2\xb8>?hl\xf6\xed7}\xb7\xbfQw\x06H\x93\xe5\xc3"
        extracted_payload = bytes(int(self.key[i: i + 8], 2) for i in range(0, len(self.key), 8))
        extracted_payload = bytes([a ^ b for a, b in zip(xor_key, extracted_payload)])

        return extracted_payload, self.payloadB == str(hashlib.sha256(extracted_payload).digest()), hashlib.sha256(
            extracted_payload).digest()

    def run(self, steganograms, hash, mode):
        if mode == "MISSING":
            self.insertMissing(steganograms)
        else:
            self.extractKey(steganograms)
        missing_indexes = self.getMissingIndexes()
        print("Missing indexes:\t", missing_indexes)

        if len(missing_indexes) == 0:
            self.payloadB = hash
            self.formKey()
            key, result, computed_hash = self.interpretKey()
            self.sorted_indexes = []

            return key, result, computed_hash
        else:
            return missing_indexes, 0, 0
