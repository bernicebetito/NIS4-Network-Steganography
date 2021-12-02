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
      print (i.options[0].oflw)

      for ctr in range(1,5):
        temp_hex = binascii.hexlify(bytes(i.options[ctr])[3:])
        temp_bin = bin(int(temp_hex,16))[2:]
        temp_bin = ("0" * (8 - len(temp_bin))) + temp_bin
        temp_bin = temp_bin[:4]
        self.test_extract += temp_bin


  # Compare the binary payload and the binary extracted
  #print(payloadA, end="\n\n")
  #print(test_extract, end="\n\n")
  #print("Checker:" + payloadA == test_extract, end="\n\n")

  def interpretKey(self):
    # Turn the binary into bytes
    extracted_payload = bytes(int(self.test_extract[i : i + 8], 2) for i in range(0, len(self.test_extract), 8))

    # Compare the hash value of payload and extracted payload
    print(self.payloadB.digest())
    print(hashlib.sha256(extracted_payload).digest(), end="\n\n")
    print("Checker:", self.payloadB.digest() == hashlib.sha256(extracted_payload).digest(), end="\n\n")

    return extracted_payload, self.payloadB.digest() == hashlib.sha256(extracted_payload).digest(), hashlib.sha256(extracted_payload).digest()

    # Comparing the original key and extracted payload
    #print(key)
    #print(bytes(extracted_payload))
    #print("Checker:", key == bytes(extracted_payload))

  def run(self, steganograms, hash):
    self.extractKey(steganograms)
    self.payloadB = hash
    key, result, computed_hash = self.interpretKey()

    return key, result, computed_hash