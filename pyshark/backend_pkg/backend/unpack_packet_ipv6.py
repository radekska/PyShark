import struct
from .basic_functions import get_ipv6


class IPv6:
    def __init__(self, data):
        self.payload_lgth, self.next_header, self.hop_lmt, src, dest = struct.unpack('! 4x H B B 16s 16s', data[:40])
        self.src = get_ipv6(src)
        self.dest = get_ipv6(dest)
        self.data = data[40:]
