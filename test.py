from scapy.all import *

timestamp_option = b'\x44\x04\x05\x50\x00\x00\x00\x00\x44\x04\x05\x60\x00\x00\x00\x00\x44\x04\x05\x70\x00\x00\x00\x00\x44\x04\x05\x80\x00\x00\x00\x00\x44\x04\x05\x90'
pkt_with_opts=IP(dst='10.1.0.1', options=IPOption(timestamp_option)) / UDP(sport=5792, dport=80)
pkt_with_opts.show2()

pkt_without_opts=IP(dst='10.1.0.1') / UDP(sport=5792, dport=80)

hexdump = hexdump(pkt_with_opts)

print(len(pkt_without_opts[IP].options))
print(len(pkt_with_opts[IP].options))
