import socket
import os

# Create a raw socket
def create_socket():
    try:
        # AF_PACKET for Linux, AF_INET for Windows with SOCK_RAW and IPPROTO_IP
        # For Windows, you might need to run the script with administrative privileges
        if os.name == "nt":
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        else:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        return s
    except Exception as e:
        print("Error creating socket: ", e)
        return None

# Configure the socket and start sniffing
def sniff_packets(socket):
    if os.name == "nt":
        host = socket.gethostbyname(socket.gethostname())
        socket.bind((host, 0))
        socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            raw_data, addr = socket.recvfrom(65535)
            print("Packet received from:", addr)
            print(raw_data)
    except KeyboardInterrupt:
        if os.name == "nt":
            socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print("Stopping packet sniffing")

# Main function to setup the sniffer
def main():
    s = create_socket()
    if s:
        sniff_packets(s)

if __name__ == "__main__":
    main()

