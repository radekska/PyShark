import struct
import socket
from .basic_functions import get_mac_addr


class Ethernet:
    def __init__(self, raw_data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', raw_data[:14])
        self.dest_mac = get_mac_addr(dest_mac)
        self.src_mac = get_mac_addr(src_mac)
        self.proto = socket.htons(proto)
        self.data = raw_data[14:]

