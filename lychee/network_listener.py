# -*- coding: utf-8 -*-
from operator import attrgetter
import logging
import struct

import dpkt
from netifaces import interfaces, ifaddresses, AF_INET

from sniff import PcapWrapper
import http


ACK = dpkt.tcp.TH_ACK
SYN = dpkt.tcp.TH_SYN
FIN = dpkt.tcp.TH_FIN
RST = dpkt.tcp.TH_RST
PUSH = dpkt.tcp.TH_PUSH


def ipaddr_string(addr):
    return '.'.join(str(octet) for octet in struct.unpack('B' * len(addr), addr))


class NetworkFileListener(object):

    def __init__(self, interface=None, mime_types=None):
        self.pc = None
        self.on_file_complete = None
        self.packet_streams = {}

        self.local_ips = self.detect_local_ips()

        logging.info("Local IP Addresses: %s" % ', '.join(self.local_ips))

        self.interface = interface
        self.mime_types = mime_types

    def detect_local_ips(self):
        """Determine all of the local ip addresses for this machine

        This allows us to flag traffic as inbound or outbound.

        """
        result = set()

        for ifaceName in interfaces():
            try:
                address = [i['addr'] for i in ifaddresses(ifaceName)[AF_INET]]
            except:
                pass

            result.add(address[0])

        return tuple(result)

    def start(self):
        if self.pc is not None:
            raise Exception('Already listening.')

        self.pc = PcapWrapper(self.interface, filters='tcp')

        try:
            self.pc.loop(self._on_packet)
        except KeyboardInterrupt:
            pass

        if self.pc.human_stats is not None:
            logging.info(self.pc.human_stats)

    def _on_packet(self, pkt):
        try:
            self._handle_packet(pkt)
        except Exception as e:
            logging.exception(e)

    def _parse_tcp_packet(self, data):
        if len(data) == 0 or data is None:
            return None

        if data.startswith('GET') or data.startswith('POST'):
            return None

        try:
            return dpkt.http.Reqsponse(data)
        except:
            pass

        return None

    def _handle_packet(self, pkt):
        eth = dpkt.ethernet.Ethernet(pkt)
        ip = eth.data
        tcp = ip.data
        data = tcp.data

        is_outbound = ipaddr_string(ip.dst) not in self.local_ips
        direction = 'outbound' if is_outbound else 'inbound'

        connection_hash = hash_packet(eth, outbound=is_outbound)

        if ipaddr_string(ip.src) in self.local_ips and ipaddr_string(ip.dst) in self.local_ips:
            # ignore packets that exist only on this computer
            return


        # lets first check if this is a http request instead of a response
        if data.startswith('GET') or data.startswith('POST'):
            if is_outbound:
                # ignore inbound http request
                _msg = 'Detected an %s HTTP Request from %s to %s'
                logging.debug(_msg % (direction, ipaddr_string(ip.src), ipaddr_string(ip.dst)))

                self._handle_request(connection_hash, tcp)

        elif not is_outbound:
            stream = self.packet_streams.get(connection_hash)
            if stream is not None:
                self._handle_response(stream, tcp)

    def _handle_request(self, connection_hash, tcp_pkt):

        if http.has_complete_headers(tcp_pkt.data):
            req = http.parse_request(tcp_pkt.data)

            logging.debug('Request URL: %s' % req['host'] + req['path'])

        logging.debug('Storing stream %s.' % connection_hash)
        self.packet_streams[connection_hash] = TcpStream(connection_hash)

    def _delete_stream(self, stream):
        if stream.id in self.packet_streams:
            del self.packet_streams[stream.id]

    def _handle_response(self, stream, tcp_pkt):
        had_headers = (stream.headers is not None)

        stream.add_packet(tcp_pkt)

        if not had_headers and stream.headers is not None:
            # this will happen the first packet that contain http header
            if self.mime_types is not None:
                mime_type = stream.headers.get('content-type', '').split(';')[0].strip()
                if mime_type not in self.mime_types:
                    logging.debug('Ignoring mime_type %s' % mime_type)
                    self._delete_stream(stream)
                    return

        if stream.is_finished:
            if stream.id not in self.packet_streams:
                # probably just a retransmission
                return

            self._delete_stream(stream)

            if stream.is_valid:
                self._on_request_complete(stream)
            else:
                _msg = "Stream was invalid at %.1f%% with %i bytes loaded"
                logging.error(_msg % (stream.progress * 100, stream.http_bytes_loaded))
                if self.pc.human_stats is not None:
                    logging.info(self.pc.human_stats)

    def _on_request_complete(self, stream):
        headers = stream.headers

        if headers is not None:
            mime_type = headers.get('content-type')
            _msg = "Successfully observed a file with %i bytes and mime-type %s"
            logging.info(_msg % (stream.http_content_length, stream.headers.get('content-type', '')))

            f = RawFile(stream.bytes(), mime_type)
            self._on_file_complete(f)

    def _on_file_complete(self, f):
        if self.on_file_complete is not None:
            self.on_file_complete(f)


def iter_packets(iterable):
    """Sorts an iterable of packets and removes the duplicates"""
    prev = None

    for i in sorted(iterable, key=attrgetter('seq')):
        if prev is None or prev.seq != i.seq:
            prev = i
            yield i


def hash_packet(eth, outbound=False):
    """Hashes a packet to determine the tcp stream it is part of """
    ip = eth.data
    tcp = ip.data

    return '%s:%i' % (ipaddr_string(ip.dst if outbound else ip.src),
                      tcp.sport if outbound else tcp.dport
                      )


def parse_flags(flags):
    result = []

    for flag, name in ((ACK, 'ACK'), (SYN, 'SYN'), (PUSH, 'PUSH'), (RST, 'RST')):
        if flags & flag:
            result.append(name)
    return result


class RawFile(object):

    def __init__(self, data, mime_type):
        self.bytes = data
        self.mime_type = mime_type


class TcpStream(object):

    def __init__(self, id):
        self.id = id
        self.buffer = {}

        self.packet_buffer = []

        self.base_seq = None
        self.next_seq = None

        self.header_data = ''
        self.headers = None
        self.is_http = None
        self.is_finished = False
        self.is_valid = True

        self.http_content_length = None
        self.http_bytes_loaded = 0

    def add_packet(self, packet):
        if self.is_finished:
            return

        #vals = []
        #for k in ('ack', 'dport', 'flags', 'off', 'off_x2', 'seq', 'sport', 'sum', 'urp', 'win'):
        #       vals.append('%s=%s' % (k, getattr(packet, k)))
        #vals.append(parse_flags(packet.flags))

        if self.base_seq is None:
            # we do not yet know the first

            if packet.data.startswith('HTTP'):
                self.is_http = True
                self._on_first_packet(packet)
            else:
                self.buffer[packet.seq] = packet

        else:
            if packet.seq == self.next_seq:
                # the exact next packet
                self._on_next_packet(packet)
            elif packet.seq < self.next_seq:
                # retransmission
                pass
            else:
                #out of order packet
                self.buffer[packet.seq] = packet

                # if the buffer grows to be bigger than 2K assume something went wrong
                if len(self.buffer) > 2000:
                    self.is_finished = True
                    self.is_valid = False
                    logging.error('Packet buffer filled up')

    def rel_seq(self, packet):
        return packet.seq - self.base_seq

    def bytes(self):
        return self.packet_buffer

    @property
    def progress(self):
        if self.http_content_length is None:
            return 0

        if self.http_content_length in (0, self.http_bytes_loaded):
            return 1

        return float(self.http_bytes_loaded) / float(self.http_content_length)

    def _on_first_packet(self, packet):
        # check if this is actually the first packet
        if self.base_seq is None:
            self.base_seq = packet.seq

        self.next_seq = packet.seq
        self._on_next_packet(packet)

    def _on_next_packet(self, packet):
        self._append_packet(packet)
        self._check_buffer()

    def _check_buffer(self):
        """Looks in the buffer to see if we have the next packet, if so append
        it and continue till there are no packets left.
        """

        count = 0
        for packet in self.remove_buffered_packets():
            self._append_packet(packet)
            count += 1

        if count > 0:
            logging.debug('Removed %i items from the buffer, %i left.' % (count, len(self.buffer)))

    def remove_buffered_packets(self):
        """Iterates over next packets in the buffer and removes them"""
        seq = self.next_seq
        while True:
            p = self.buffer.pop(seq, None)
            if p is None:
                break
            else:
                seq += len(p.data)
                yield p

    def _append_packet(self, packet):
        """Appends a packet to the end of the list of received packets and processes it"""
        self.next_seq += len(packet.data)

        if self.headers is not None:
            self.packet_buffer.append(packet.data)
            self.http_bytes_loaded += len(packet.data)
        else:
            self.header_data += packet.data

        # check if we have enough packets for the entire http header
        if self.is_http and self.headers is None:
            if http.has_complete_headers(self.header_data):
                resp = http.parse_response(self.header_data)
                self.header_data = None
                self.packet_buffer.append(resp['body'])
                self.headers = resp['headers']
                self.http_bytes_loaded = len(resp['body'])

                self._on_http_headers()

        # check if we have finished the request
        if self.http_content_length is not None:

            if self.http_content_length == self.http_bytes_loaded:
                self.is_finished = True
            elif self.http_content_length < self.http_bytes_loaded:
                logging.error("Received data was longer than the content length header")
                self.is_valid = False
                self.is_finished = True

        self._handle_ordered_packet(packet)

    def _on_last_packet(self, packet):
        self.is_finished = True

    def _handle_ordered_packet(self, packet):
        """This will eventually provide a way for a callback receive packets in order"""
        pass

    def _on_http_headers(self):
        content_length = self.headers.get('content-length', None)

        if content_length is not None:
            content_length = int(content_length)

            self.http_content_length = content_length
