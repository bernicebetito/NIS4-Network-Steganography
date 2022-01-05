# Packet creation / manipulation
from scapy.all import *
# Turn payload into byte
import binascii
# Hash equivalent of key
import hashlib

class extractionClass (object):

  def extractKey(self, steganograms):
    self.test_extract = ""
    for i in steganograms:
      if "google" in i[DNS].qd.qname.decode():
          steganograms.sort()
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
                      self.test_extract += temp_bin
                  else:
                      payload_ctr = True


  # Compare the binary payload and the binary extracted
  #print(payloadA, end="\n\n")
  #print(test_extract, end="\n\n")
  #print("Checker:" + payloadA == test_extract, end="\n\n")

  def interpretKey(self):
    # Turn the binary into bytes
    xor_key = b"M\x80Q\xa7\x0b\x0c'h\x80\xc5\x9d@\xa1\xb2\xb8>?hl\xf6\xed7}\xb7\xbfQw\x06H\x93\xe5\xc3"
    extracted_payload = bytes(int(self.test_extract[i : i + 8], 2) for i in range(0, len(self.test_extract), 8))
    extracted_payload = bytes([a ^ b for a, b in zip(xor_key, extracted_payload)])
    # Compare the hash value of payload and extracted payload
    #print(self.payloadB)
    #print(hashlib.sha256(extracted_payload).digest(), end="\n\n")
    #print("Checker:", self.payloadB == str(hashlib.sha256(extracted_payload).digest()), end="\n\n")

    return extracted_payload, self.payloadB == str(hashlib.sha256(extracted_payload).digest()), hashlib.sha256(extracted_payload).digest()

    # Comparing the original key and extracted payload
    #print(key)
    #print(bytes(extracted_payload))
    #print("Checker:", key == bytes(extracted_payload))

  def run(self, steganograms, hash):
    self.extractKey(steganograms)
    self.payloadB = hash
    key, result, computed_hash = self.interpretKey()

    return key, result, computed_hash
