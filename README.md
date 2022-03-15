# NIS4-Network-Steganography
A study which aims to explore the use of network steganography.

## Use
This study explores the possibility of using network steganography in concealing symmetric keys in its distribution

## Pre-requisites
1. Python / Python3
  * Programming language used.
  * To download in **Linux**: `sudo apt-get install python3`
  * To download in **Windows**: [Python for Windows](https://www.python.org/downloads/windows/)
2. Curl
  * Command that allows the transfer (upload / download) of data using command line interface.
  * To download in **Linux**: `sudo apt-get install curl`
  * To download in **Windows**: [Curl for Windows](https://curl.se/windows/)
3. Pip
  * Tool which helps in installing packages written in Python.
  * To download in **Linux**: `sudo apt-get install pip`
  * To download in **Windows**: [Pip for Windows](https://pip.pypa.io/en/stable/installation/)
4. Scapy
  * A packet manipulation tool.
  * To download in **Linux**: `sudo apt-get install scapy`
  * To download in **Windows**: `pip install scapy`
5. Pyrcryptodome
  * A Python library for cryptographic techniques.
  * To download in **Linux**: `sudo pip install pycryptodome`
  * To download in **Windows**: `pip install pycryptodome`

## Download
Download the project through the following commands:
* Linux:
``` sudo curl -L -O https://github.com/bernicebetito/NIS4-Network-Steganography/archive/master.zip ```
* Windows:
``` curl -L -O https://github.com/bernicebetito/NIS4-Network-Steganography/archive/master.zip ```

Once downloaded, the project can be used through the following commands:
* For the server:
  * Linux: `sudo python3 server.py`
  * Windows: `python server.py`
* For the client:
  * Linux: `sudo python3 client.py`
  * Windows: `python client.py`

Note:  
_The IP address of the server would be needed upon running the server and client._

## Guide
To test the sorting of the steganograms, steganograms are intentionally shuffled before sending. Additionally, only a certain amount of steganograms are first sent in order to test the program's ability to determine if there are missing steganograms as well as it's ability to find and send these steganograms. 