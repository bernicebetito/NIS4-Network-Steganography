import socket, json, sys, traceback, re, scapy
from scapy.all import *

# JSON Return Codes
begin = '{"command":"ret_code", "code":"BEGIN"}'
success = '{"command":"ret_code", "code":"SUCCESS"}'
error = '{"command":"ret_code", "code":"ERROR"}'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Function to convert a json object into a python object
def to_python(jsonObj):
    data = json.loads(jsonObj)
    return data


# Function to convert a python object into a json object
def to_json(pythonObj):
    data = json.dumps(pythonObj)
    return data

class StegServer(object):

    def __init__(self, server_host, server_port):
        try:
            global sock

            # Bind socket
            sock.bind((server_host, server_port))
            print("Server online...")
        
        except Exception as e:
            print(str(e))
            traceback.print_exc(e)
            sock.close()
            sys.exit()

    def handle(self):
        global sock
        self.ready_to_receive = 0
        self.finished_receiving = False

        while True:
            try:
                # Receive incoming message
                self.data = sock.recvfrom(1024)
                self.message = to_python(self.data[0])
                self.clientAddress = self.data[1]

                # Handle Begin Transmission Message
                if self.message["command"] == "begin" and self.ready_to_receive == 0:
                    self.ready_to_receive = 1

                    # Ready return code
                    self.startTransmissionResponse = to_python(begin)
                    self.startTransmissionResponseJSON = to_json(self.startTransmissionResponse)

                    # Send return code
                    sock.sendto(bytes(self.startTransmissionResponseJSON, "utf-8"), self.clientAddress)
                    print("Client " + str(self.clientAddress) + " has connected and will start sending steganograms.")

                    # Begin Sniffing Steganograms
                    sniff_thread = AsyncSniffer(filter='port 11234')
                    sniff_thread.start()
                    print("Sniff started")

                # Handle Stop Transmission Message
                if self.message["command"] == "stop" and self.ready_to_receive == 1:
                    self.ready_to_receive = 0

                    # Stop Sniffing Steganograms
                    self.finished_receiving = True
                    steganograms = sniff_thread.stop()
                    print(str(len(steganograms)))
                    for i in steganograms:
                        for j in i.options:
                            print(i.option[j].oflw)

                    # Ready return code
                    self.stopTransmissionResponse = to_python(success)
                    self.stopTransmissionResponseJSON = to_json(self.stopTransmissionResponse)
                    print("Client " + str(self.clientAddress) + " has finished sending steganograms.")
                    print("Key hash received: " + self.message["key_hash"])

                    # Send return code
                    sock.sendto(bytes(self.stopTransmissionResponseJSON, "utf-8"), self.clientAddress)

            except Exception as e:
                print(str(e))
                traceback.print_exc(e)
                sock.close()
                sys.exit()

def main():
    global sock

    regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    while True:
        # Set variables for server address and server port
        server_host = input('Input server address: ')
        server_port = 5555

        result = bool(re.match(regex, server_host))
        if (result):
            break
        else:
            print("Invalid IP Address, please try again.\n")

    # Initialize server
    steg_server = StegServer(server_host, server_port)

    # Process incoming messages
    steg_server.handle()

if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        input("Service has been interrupted, press any key to exit...")
        sock.close()
        sys.exit()
