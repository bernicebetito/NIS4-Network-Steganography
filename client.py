import socket, json, sys, traceback, re

# JSON commands
begin = '{"command":"begin", "packet_count":""}'
stop = '{"command":"stop", "key_hash":""}'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ready_to_receive = 0

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
                global ready_to_receive
                ready_to_receive = 1
            
            elif self.return_code["code"] == "ERROR":
                print("An unexpected error has occured")

            else:
                print("An unexpected error has occured")

        except Exception as e:
            print(str(e))
            traceback.print_exc(e)
            sock.close()
            sys.exit()

    def send_steganograms(self):
        try:
            global sock
            global ready_to_receive
            input("Ready to send steganograms, press any key to continue...")

            # Send steganograms

            # Ready Stop Transmission Message and send to server
            key_hash = "fb276d832de6b6a7bb5ea6df7d29e90a45ae6490"
            self.stopTransmissionRequest = to_python(stop)
            self.stopTransmissionRequest["key_hash"] = key_hash
            self.stopTransmissionRequestJSON = to_json(self.stopTransmissionRequest)
            sock.sendto(bytes(self.stopTransmissionRequestJSON, "utf-8"), (self.server_host, self.server_port))

            # Process return code
            self.data = sock.recv(1024)
            self.return_code = to_python(self.data.decode("utf-8"))

            if self.return_code["code"] == "SUCCESS":
                print("Success, server received all steganograms.")
                global ready_to_receive
                ready_to_receive = 1
            
            elif self.return_code["code"] == "ERROR":
                print("An unexpected error has occured")

            else:
                print("An unexpected error has occured")

            input("Steganograms have been successfully sent, press any key to continue...")
            ready_to_receive = 0

        except Exception as e:
            print(str(e))
            traceback.print_exc(e)
            sock.close()
            sys.exit()

regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
while True:
    # Set variables for server address and destination port
    server_host = input('Enter IP address of server: ')
    server_port = 12345

    result = bool(re.match(regex, server_host))
    if (result):
        break
    else:
        print("Invalid IP Address, please try again.\n")

# Initialize client
steg_client = StegClient(server_host, server_port)

# Attempt to connect to server
while ready_to_receive == 0:
    steg_client.connect_to_server()

# Send steganograms
while ready_to_receive == 1:
    steg_client.send_steganograms()

sock.close()