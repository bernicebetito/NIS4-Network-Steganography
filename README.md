# NIS4-Network-Steganography

## Module Sub Tasks
### Symmetric Key Generation Module
- [ ] Produce 256 Bits / 32 Bytes of random data which will act as the symmetric key

### Steganogram Preparation Module
- [ ] Gather the necessary information
  - [ ]  Size of payload in bits
  - [ ]  Number of bits allotted in each packet
  - [ ]  Total number of steganograms needed
  - [ ]  Source and Destination Addresses
  - [ ]  Dummy domain
- [ ] Create the steganograms with the information gathered

### Payload Insertion Module
- [ ] Create hash of payload
- [ ] Convert payload into binary
- [ ] Store payload (binary form) into the steganograms

### Connection Module
- [ ] Create the UDP Server (Receiver)
  - [ ] Create the Server Handler
  - [ ] Create the packet sniffer for steganograms
- [ ] Create the UDP Client (Sender)

### Control Module
- [ ] Command Messages
  - [ ] Begin Transmission
  - [ ] Stop Transmission
  - [ ] Return Codes

### Payload Extraction Module
- [ ] Save received packets into pcap file
- [ ] Parse pcap file and save into list
- [ ] Sort packets according to sequence number
- [ ] Read key segments from packets and concatenate to form whole key

### Key Interpretation Module
- [ ] Hash symmetric key
- [ ] Compare hash with hash received from Sender
