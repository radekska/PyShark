import sys
import socket
import tkinter
import textwrap
import collections
from datetime import datetime as dt
from pyshark.backend_pkg.backend import Ethernet, IPv4, IPv6, UDP, TCP, SCTP, ICMP

""" Global frame counter var """
frame_cnt = 0


class Sniff:
    """

    This backend class creates raw socket on port 65536 and sniffs all packets
    coming to device which program is running on.

    """

    def __init__(self):
        self.conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        self.thread_kill = True
        self.json_data = []

    def run_sniff(self, filter_options):
        global frame_cnt

        try:
            while self.thread_kill:
                raw_data, addr = self.conn.recvfrom(65536)
                eth = Ethernet(raw_data)

                frame_time = "{}:{}:{}.{}".format(dt.now().time().hour, dt.now().minute, dt.now().second,
                                                  str(dt.now().microsecond)[:3])

                self.json_data.append({"Ethernet": {"FrameCnt": frame_cnt,
                                                    "Time": "",
                                                    "MAC": {"Dest": "", "Source": "", "Protocol": ""}}})

                self.json_data[frame_cnt]["Ethernet"]["MAC"]["Dest"] = eth.dest_mac
                self.json_data[frame_cnt]["Ethernet"]["MAC"]["Source"] = eth.src_mac
                self.json_data[frame_cnt]["Ethernet"]["MAC"]["Protocol"] = eth.proto
                self.json_data[frame_cnt]["Ethernet"]["Time"] = frame_time

                # eth proto == 8 then its IPv4      (0x0008)
                if eth.proto == 8 and (filter_options[0] == "All" or filter_options[0] == "IPv4"):
                    ipv4 = IPv4(eth.data)
                    self.json_data[frame_cnt]["Ethernet"].update({
                        "IPv4": {"Dest": "", "Source": "", "Protocol": "", "Version": "",
                                 "Header": "", "TTL": ""}})

                    self.json_data[frame_cnt]["Ethernet"]["IPv4"]["Dest"] = ipv4.dest
                    self.json_data[frame_cnt]["Ethernet"]["IPv4"]["Source"] = ipv4.src
                    self.json_data[frame_cnt]["Ethernet"]["IPv4"]["Protocol"] = ipv4.ip_proto
                    self.json_data[frame_cnt]["Ethernet"]["IPv4"]["TTL"] = ipv4.ttl
                    self.json_data[frame_cnt]["Ethernet"]["IPv4"]["Header"] = ipv4.header
                    self.json_data[frame_cnt]["Ethernet"]["IPv4"]["Version"] = ipv4.ver

                    # ip proto == 6 then its TCP
                    if ipv4.ip_proto == 6 and len(ipv4.data) > 13 and (
                            filter_options[1] == "All" or filter_options[1] == "TCP"):

                        tcp = TCP(ipv4.data)

                        self.json_data[frame_cnt]["Ethernet"].update({
                            "TCP": {"Dest": "", "Source": "", "SEQ": "", "ACKN": "",
                                    "FLAGS": {"URG": "", "ACK": "", "PSH": "", "RST": "", "SYN": "",
                                              'FIN': ""}},
                            "Data": ""})

                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["SEQ"] = tcp.sequence
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["ACKN"] = tcp.acknowledge
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["Source"] = tcp.src_port
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["Dest"] = tcp.dest_port
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["FLAGS"]["FIN"] = tcp.flag_fin
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["FLAGS"]["ACK"] = tcp.flag_ack
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["FLAGS"]["SYN"] = tcp.flag_syn
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["FLAGS"]["RST"] = tcp.flag_rst
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["FLAGS"]["PSH"] = tcp.flag_psh
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["FLAGS"]["URG"] = tcp.flag_urg
                        self.json_data[frame_cnt]["Ethernet"]["Data"] = tcp.data

                    # ip proto == 17 then its UDP
                    elif ipv4.ip_proto == 17 and len(ipv4.data) > 7 and (
                            filter_options[1] == "All" or filter_options[1] == "UDP"):

                        udp = UDP(ipv4.data)

                        self.json_data[frame_cnt]["Ethernet"].update({
                            "UDP": {"Dest": "", "Source": "", "Size": ""},
                            "Data": ""})

                        self.json_data[frame_cnt]["Ethernet"]["UDP"]["Size"] = udp.size
                        self.json_data[frame_cnt]["Ethernet"]["UDP"]["Source"] = udp.src_port
                        self.json_data[frame_cnt]["Ethernet"]["UDP"]["Dest"] = udp.dest_port
                        self.json_data[frame_cnt]["Ethernet"]["Data"] = udp.data

                    # ip proto == 1 then its ICMP
                    elif ipv4.ip_proto == 1 and len(ipv4.data) > 3 and (
                            filter_options[1] == "All" or filter_options[1] == "ICMP"):

                        icmp = ICMP(ipv4.data)
                        self.json_data[frame_cnt]["Ethernet"].update({
                            "ICMP": {"Type": "", "Code": "", "Checksum": ""},
                            "Data": ""})

                        self.json_data[frame_cnt]["Ethernet"]["ICMP"]["Type"] = icmp.icmp_type
                        self.json_data[frame_cnt]["Ethernet"]["ICMP"]["Code"] = icmp.code
                        self.json_data[frame_cnt]["Ethernet"]["ICMP"]["Checksum"] = icmp.checksum
                        self.json_data[frame_cnt]["Ethernet"]["Data"] = icmp.data

                    elif ipv4.ip_proto == 132 and (
                            filter_options[1] == "All" or filter_options[1] == "SCTP"):

                        sctp = SCTP(ipv4.data)
                        self.json_data[frame_cnt]["Ethernet"].update({
                            "SCTP": {"Dest": "", "Source": "", "VerTag": "", "Checksum": ""},
                            "Data": ""})

                        self.json_data[frame_cnt]["Ethernet"]["SCTP"]["Dest"] = sctp.dest_port
                        self.json_data[frame_cnt]["Ethernet"]["SCTP"]["Source"] = sctp.src_port
                        self.json_data[frame_cnt]["Ethernet"]["SCTP"]["VerTag"] = sctp.ver_tag
                        self.json_data[frame_cnt]["Ethernet"]["SCTP"]["Checksum"] = sctp.ver_tag
                        self.json_data[frame_cnt]["Ethernet"]["SCTP"]["Chunks"] = sctp.chunks


                    else:
                        return None
                        # self.json_data[i]["Ethernet"].update({
                        #      "Data": ""})
                        # self.json_data[i]["Ethernet"]["Data"] = ipv4.data

                # eth proto == 56710 then its IPv6  (0xDD86)
                elif eth.proto == 56710 and (filter_options[0] == "All" or filter_options[0] == "IPv6"):
                    ipv6 = IPv6(eth.data)

                    self.json_data[frame_cnt]["Ethernet"].update({
                        "IPv6": {"Dest": "", "Source": "", "Hop Limit": "", "Next Header": "", "Payload Length": ""}})

                    self.json_data[frame_cnt]["Ethernet"]["IPv6"]["Dest"] = ipv6.dest
                    self.json_data[frame_cnt]["Ethernet"]["IPv6"]["Source"] = ipv6.src
                    self.json_data[frame_cnt]["Ethernet"]["IPv6"]["Hop Limit"] = ipv6.hop_lmt
                    self.json_data[frame_cnt]["Ethernet"]["IPv6"]["Next Header"] = ipv6.next_header
                    self.json_data[frame_cnt]["Ethernet"]["IPv6"]["Payload Length"] = ipv6.payload_lgth

                    if ipv6.next_header == 6 and len(ipv6.data) > 13 and (
                            filter_options[1] == "All" or filter_options[1] == "TCP"):

                        tcp = TCP(ipv6.data)

                        self.json_data[frame_cnt]["Ethernet"].update({
                            "TCP": {"Dest": "", "Source": "", "SEQ": "", "ACKN": "",
                                    "FLAGS": {"URG": "", "ACK": "", "PSH": "", "RST": "", "SYN": "",
                                              'FIN': ""}},
                            "Data": ""})

                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["SEQ"] = tcp.sequence
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["ACKN"] = tcp.acknowledge
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["Source"] = tcp.src_port
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["Dest"] = tcp.dest_port
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["FLAGS"]["FIN"] = tcp.flag_fin
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["FLAGS"]["ACK"] = tcp.flag_ack
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["FLAGS"]["SYN"] = tcp.flag_syn
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["FLAGS"]["RST"] = tcp.flag_rst
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["FLAGS"]["PSH"] = tcp.flag_psh
                        self.json_data[frame_cnt]["Ethernet"]["TCP"]["FLAGS"]["URG"] = tcp.flag_urg
                        self.json_data[frame_cnt]["Ethernet"]["Data"] = tcp.data

                        # ip proto == 17 then its UDP
                    elif ipv6.next_header == 17 and len(ipv6.data) > 7 and (
                            filter_options[1] == "All" or filter_options[1] == "UDP"):

                        udp = UDP(ipv6.data)

                        self.json_data[frame_cnt]["Ethernet"].update({
                            "UDP": {"Dest": "", "Source": "", "Size": ""},
                            "Data": ""})

                        self.json_data[frame_cnt]["Ethernet"]["UDP"]["Size"] = udp.size
                        self.json_data[frame_cnt]["Ethernet"]["UDP"]["Source"] = udp.src_port
                        self.json_data[frame_cnt]["Ethernet"]["UDP"]["Dest"] = udp.dest_port
                        self.json_data[frame_cnt]["Ethernet"]["Data"] = udp.data

                        # ip proto == 1 then its ICMP
                    elif (ipv6.next_header == 1 or ipv6.next_header == 58) and len(ipv6.data) > 3 and (
                            filter_options[1] == "All" or filter_options[1] == "ICMP"):

                        icmp = ICMP(ipv6.data)
                        self.json_data[frame_cnt]["Ethernet"].update({
                            "ICMP": {"Type": "", "Code": "", "Checksum": ""},
                            "Data": ""})

                        self.json_data[frame_cnt]["Ethernet"]["ICMP"]["Type"] = icmp.icmp_type
                        self.json_data[frame_cnt]["Ethernet"]["ICMP"]["Code"] = icmp.code
                        self.json_data[frame_cnt]["Ethernet"]["ICMP"]["Checksum"] = icmp.checksum
                        self.json_data[frame_cnt]["Ethernet"]["Data"] = icmp.data

                    elif ipv6.next_header == 132 and (
                            filter_options[1] == "All" or filter_options[1] == "SCTP"):

                        sctp = SCTP(ipv6.data)
                        self.json_data[frame_cnt]["Ethernet"].update({
                            "SCTP": {"Dest": "", "Source": "", "VerTag": "", "Checksum": ""},
                            "Data": ""})

                        self.json_data[frame_cnt]["Ethernet"]["SCTP"]["Dest"] = sctp.dest_port
                        self.json_data[frame_cnt]["Ethernet"]["SCTP"]["Source"] = sctp.src_port
                        self.json_data[frame_cnt]["Ethernet"]["SCTP"]["VerTag"] = sctp.ver_tag
                        self.json_data[frame_cnt]["Ethernet"]["SCTP"]["Checksum"] = sctp.ver_tag
                        self.json_data[frame_cnt]["Ethernet"]["SCTP"]["Chunks"] = sctp.chunks


                    else:
                        return None

                frame_cnt += 1
                return self.json_data[frame_cnt - 1]
        except RuntimeError:
            sys.exit()


class Insert:
    """

    This backend class takes json data, formats it and inserts to Tkinter treeview.

    """

    @staticmethod
    def unpack_and_insert(row, text_box, thread_kill0):

        if thread_kill0:
            i = row[1].get('FrameCnt')
            time = row[1].get('Time')
            data = row[1].get('Data')

            # flags

            is_ipv4 = False
            is_ipv6 = False
            is_tcp = False
            is_udp = False
            is_icmp = False
            is_sctp = False

            protocol = None
            ether_frame = None

            """ UNPACK JSON DATA """

            if row:
                if row[1].get('IPv4') is not None:
                    ipv4_src = row[1].get('IPv4').get('Source')
                    ipv4_dst = row[1].get('IPv4').get('Dest')
                    ttl = row[1].get('IPv4').get('TTL')
                    protocol = row[1].get('IPv4').get('Protocol')
                    version = row[1].get('IPv4').get('Version')
                    header = row[1].get('IPv4').get('Header')

                    mac_src = row[1].get('MAC').get('Source')
                    mac_dst = row[1].get('MAC').get('Dest')
                    mac_proto = row[1].get('MAC').get('Protocol')

                    is_ipv4 = True

                if row[1].get('IPv6') is not None:
                    ipv6_src = row[1].get('IPv6').get('Source')
                    ipv6_dst = row[1].get('IPv6').get('Dest')
                    hop_lmt = row[1].get('IPv6').get('Hop Limit')
                    protocol = row[1].get('IPv6').get('Next Header')
                    # payload_length = row[1].get('IPv6').get('Payload Lenght')

                    mac_src = row[1].get('MAC').get('Source')
                    mac_dst = row[1].get('MAC').get('Dest')
                    mac_proto = row[1].get('MAC').get('Protocol')

                    is_ipv6 = True

                if protocol == 6:
                    try:
                        tcp_src = row[1].get('TCP').get('Source')
                        tcp_dst = row[1].get('TCP').get('Dest')
                        is_tcp = True
                    except AttributeError:
                        pass

                elif protocol == 17:
                    try:
                        udp_src = row[1].get('UDP').get('Source')
                        udp_dst = row[1].get('UDP').get('Dest')
                        is_udp = True
                    except AttributeError:
                        pass
                elif protocol == 1 or protocol == 58:
                    try:
                        icmp_type = row[1].get('ICMP').get('Type')
                        icmp_code = row[1].get('ICMP').get('Code')
                        icmp_chksum = row[1].get('ICMP').get('Checksum')
                        is_icmp = True
                    except AttributeError:
                        pass
                elif protocol == 132:
                    try:
                        sctp_src = row[1].get('SCTP').get("Source")
                        sctp_dest = row[1].get('SCTP').get("Dest")
                        sctp_vertag = row[1].get('SCTP').get("VerTag")
                        sctp_chksum = row[1].get('SCTP').get("Checksum")
                        sctp_chunks = row[1].get('SCTP').get("Chunks")
                        is_sctp = True
                    except AttributeError:
                        pass

                """ INSERT IPV4 DATA """

                if is_ipv4 and (is_tcp or is_udp or is_icmp or is_sctp):

                    ether_frame = text_box.insert("", i, text="Frame [{}]".format(i),
                                                  values=(
                                                      time, ipv4_src, ipv4_dst, protocol, header,
                                                      "TTL = {} Version: {}".format(ttl, version)), tags='eth_tag')

                    text_box.insert(ether_frame, "end", text="MAC",
                                    values=("", mac_src, mac_dst, mac_proto), tags='mac_tag')

                    if is_tcp:
                        text_box.insert(ether_frame, "end", text="Transport Protocol",
                                        values=("", (":", tcp_src), (":", tcp_dst), "TCP"), tags='tcp_tag')
                    elif is_udp:
                        text_box.insert(ether_frame, "end", text="Transport Protocol",
                                        values=("", (":", udp_src), (":", udp_dst), "UDP"), tags='udp_tag')
                    elif is_icmp:
                        text_box.insert(ether_frame, "end", text="Transport Protocol",
                                        values=(
                                            ("", ("Type: {}".format(icmp_type)),
                                             ("Code: {}".format(icmp_code)),
                                             "ICMP", "Checksum: {}".format(icmp_chksum))), tags='icmp_tag')
                    elif is_sctp:
                        text_box.insert(ether_frame, "end", text="Transport Protocol",
                                        values=("", (":", sctp_src), (":", sctp_dest), "SCTP",
                                                "Vertag {} Checksum {}".format(sctp_vertag, sctp_chksum)),
                                        tags='udp_tag')

                        chunk_rows = text_box.insert(ether_frame, "end", text="Chunks", tags='chunk_tag')
                        sorted_chunks = collections.OrderedDict(sorted(sctp_chunks.items()))

                        for row, info in sorted_chunks.items():
                            try:
                                text_box.insert(chunk_rows, "end",
                                                values=("Chunk: {}".format(str(row)),
                                                        "Flags: {}".format(info["chnk_flags"]),
                                                        "Data: {}".format(info["chnk_data"]),
                                                        "Type: {}".format(
                                                            info["chnk_type"]),
                                                        "Length: {}".format(
                                                            info["chnk_length"])),
                                                tags='chunk_tag2')
                            except tkinter.TclError:
                                pass

                """ INSERT IPV6  DATA """

                if is_ipv6 and (is_tcp or is_udp or is_icmp or is_sctp):
                    ether_frame = text_box.insert("", i, text="Frame [{}]".format(i),
                                                  values=(
                                                      time, ipv6_src, ipv6_dst, protocol, "",
                                                      "Hop Limit = {}".format(hop_lmt)),
                                                  tags='eth_tag')
                    text_box.insert(ether_frame, "end", text="MAC",
                                    values=("", mac_src, mac_dst, mac_proto), tags='mac_tag')

                    if is_tcp:
                        text_box.insert(ether_frame, "end", text="Transport Protocol",
                                        values=("", (":", tcp_src), (":", tcp_dst), "TCP"), tags='tcp_tag')
                    elif is_udp:
                        text_box.insert(ether_frame, "end", text="Transport Protocol",
                                        values=("", (":", udp_src), (":", udp_dst), "UDP"), tags='udp_tag')
                    elif is_icmp:
                        text_box.insert(ether_frame, "end", text="Transport Protocol",
                                        values=(
                                            ("", ("Type: {}".format(icmp_type)),
                                             ("Code: {}".format(icmp_code)),
                                             "ICMP", "Checksum: {}".format(icmp_chksum))), tags='icmp_tag')
                    elif is_sctp:
                        text_box.insert(ether_frame, "end", text="Transport Protocol",
                                        values=("", (":", sctp_src), (":", sctp_dest), "SCTP", "",
                                                "Vertag = {} , Checksum = {}".format(sctp_vertag, sctp_chksum)),
                                        tags='udp_tag')

                        chunk_rows = text_box.insert(ether_frame, "end", text="Chunks", tags='chunk_tag')
                        sorted_chunks = collections.OrderedDict(sorted(sctp_chunks.items()))

                        for row, info in sorted_chunks.items():
                            try:
                                text_box.insert(chunk_rows, "end",
                                                values=("Chunk: {}".format(str(row)),
                                                        "Flags: {}".format(info["chnk_flags"]),
                                                        "Data: {}".format(info["chnk_data"]),
                                                        "Type: {}".format(
                                                            info["chnk_type"]),
                                                        "Length: {}".format(
                                                            info["chnk_length"])),
                                                tags='chunk_tag2')
                            except tkinter.TclError:
                                pass

            """ INSERT CODED DATA """

            if data is None:
                pass
            elif len(data) > 0:
                data_row = text_box.insert(ether_frame, "end", text="Data", tags='data_tag')
                data = str(data)
                wrapped_data = textwrap.wrap(data, 50)

                for row_data in wrapped_data:
                    try:
                        text_box.insert(data_row, "end",
                                        values=(row_data, "", "", "", "", "",), tags='data_tag2')
                    except tkinter.TclError:
                        pass

            """ CONFIGURE COLORS """

            text_box.tag_configure('mac_tag', background='gray31')
            text_box.tag_configure('eth_tag', background='gray13')
            text_box.tag_configure('tcp_tag', background='gray31')
            text_box.tag_configure('udp_tag', background='gray31')
            text_box.tag_configure('icmp_tag', background='gray31')
            text_box.tag_configure('data_tag2', background='gray35')
            text_box.tag_configure('data_tag', background='gray35')
            text_box.tag_configure('chunk_tag2', background='gray35')
            text_box.tag_configure('chunk_tag', background='gray35')
