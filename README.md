# NIS4-Network-Steganography

## Module Sub Tasks
### Symmetric Key Generation Module
- [X] Produce 256 Bits / 32 Bytes of random data which will act as the symmetric key

### Steganogram Preparation Module
- [x] Gather the necessary information
  - [X]  Size of payload in bits
  - [X]  Number of bits allotted in each packet
  - [X]  Total number of steganograms needed
  - [X]  Source and Destination Addresses
  - [x]  Dummy domain
- [X] Create the steganograms with the information gathered

### Payload Insertion Module
- [X] Create hash of payload
- [X] Convert payload into binary
- [X] Store payload into the steganograms

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
