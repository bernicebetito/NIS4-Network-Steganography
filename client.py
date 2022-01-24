import socket, json, sys, traceback, re, InsertionClass
from scapy.all import *

# JSON commands
begin = '{"command":"begin", "packet_count":""}'
stop = '{"command":"stop", "key_hash":""}'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
has_connected = 0
ready_to_send = 0


# Function to convert a json object into a python object
def to_python(jsonObj):
    data = json.loads(jsonObj)
    return data


# Function to convert a python object into a json object
def to_json(pythonObj):
    data = json.dumps(pythonObj)
    return data


class StegClient(object):

    def __init__(self, server_host, server_port):
        self.server_host = server_host
        self.server_port = server_port
        self.steganogram_maker = InsertionClass.InsertionClass()

    def connect_to_server(self):
        try:
            global sock
            input("Ready to connect to server, press any key to continue...")
            print("Connecting to Server...")

            # Ready Begin Transmission Message and send to server
            self.connectionRequest = to_python(begin)
            self.connectionRequest["packet_count"] = 16
            self.connectionRequestJSON = to_json(self.connectionRequest)
            sock.sendto(bytes(self.connectionRequestJSON, "utf-8"), (self.server_host, self.server_port))

            # Process return code
            self.data = sock.recv(1024)
            self.return_code = to_python(self.data.decode("utf-8"))

            if self.return_code["code"] == "BEGIN":
                print("Success, established connection with server")
                global has_connected
                has_connected = 1

            elif self.return_code["code"] == "ERROR":
                print("An unexpected error has occured")

            else:
                print("An unexpected error has occured")

        except Exception as e:
            print(str(e))
            traceback.print_exc(e)
            sock.close()
            sys.exit()

    def create_steganograms(self):
        try:
            global ready_to_send
            input("Ready to create steganograms, press any key to continue...")
            xor_key = self.steganogram_maker.getXORKey()
            self.steganograms, self.hash = self.steganogram_maker.getSteganograms(
                socket.gethostbyname(socket.gethostname()), self.server_host, xor_key)
            ready_to_send = 1

        except Exception as e:
            print(str(e))
            traceback.print_exc(e)
            sock.close()
            sys.exit()

    def send_steganograms(self):
        try:
            global sock
            global ready_to_send
            input("Ready to send steganograms, press any key to continue...")
            key_hash = self.hash
            self.stopTransmissionRequest = to_python(stop)
            self.stopTransmissionRequest["key_hash"] = str(key_hash.digest())
            self.stopTransmissionRequestJSON = to_json(self.stopTransmissionRequest)

            while ready_to_send:
                # Send steganograms
                send(self.steganograms)

                # Ready Stop Transmission Message and send to server
                input("Finished sending steganograms, press any key to continue...")
                sock.sendto(bytes(self.stopTransmissionRequestJSON, "utf-8"), (self.server_host, self.server_port))

                # Process return code
                self.data = sock.recv(1024)
                self.return_code = to_python(self.data.decode("utf-8"))

                if self.return_code["code"] == "SUCCESS":
                    print("Success, server received all steganograms.")
                    ready_to_send = 0
                    input("Steganograms have been successfully sent, press any key to continue...")

                elif self.return_code["code"] == "ERROR":
                    print("Failed, server did not receive steganograms correctly.")
                    ready_to_send = 0
                    input("Steganograms have been successfully sent, press any key to continue...")

                elif self.return_code["code"] == "MISSING":
                    print("Resending missing packets.")
                    missing_indexes = list(self.return_code["indexes"])
                    missing_indexes = [int(x) for x in missing_indexes]
                    self.steganograms = self.steganogram_maker.findSteganogram(missing_indexes)

                    missing_ret = '{"command":"missing", "key_hash":""}'
                    self.stopTransmissionRequest = to_python(missing_ret)
                    self.stopTransmissionRequest["key_hash"] = str(key_hash.digest())
                    self.stopTransmissionRequestJSON = to_json(self.stopTransmissionRequest)

                else:
                    print("An unexpected error has occured")
                    ready_to_send = 0
                    input("Steganograms have been successfully sent, press any key to continue...")

        except Exception as e:
            print(str(e))
            traceback.print_exc(e)
            sock.close()
            sys.exit()


regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
while True:
    # Set variables for server address and destination port
    server_host = input('Enter IP address of server: ')
    server_port = 5555

    result = bool(re.match(regex, server_host))
    if (result):
        break
    else:
        print("Invalid IP Address, please try again.\n")

# Initialize client
steg_client = StegClient(server_host, server_port)

# Attempt to connect to server
while has_connected == 0:
    steg_client.connect_to_server()

while ready_to_send == 0:
    steg_client.create_steganograms()

# Send steganograms
while ready_to_send == 1:
    steg_client.send_steganograms()

sock.close()