#!/usr/bin/env python

# Copyright (c) 2012 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys
import six

try:
    import gevent, gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)
except ImportError:
    gevent = None
    print >>sys.stderr, 'warning: gevent not found, using threading instead'

import socket
import select
import socketserver
import struct
import string
import hashlib
import os
import json
import logging
import getopt
import myCrypt


def get_table(key):
    table = str.maketrans('abcdefghijklmnopqrstuvwxyz', 'zyxwvutsrqponmlkjihgfedcba')
    decrypt_table = str.maketrans('zyxwvutsrqponmlkjihgfedcba', 'abcdefghijklmnopqrstuvwxyz')

    return table, decrypt_table


def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):   # Multiple inheritance
    allow_reuse_address = True


class Socks5Server(socketserver.StreamRequestHandler):
    ''' RequesHandlerClass Definition '''
    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])      # use select I/O multiplexing model
                if sock in r:                               # if local socket is ready for reading
                    data = sock.recv(4096)
                    if len(data) <= 0:                      # received all data
                        break
                    data = self.encrypt(data)
                    result = send_all(remote, data)   # send data after encrypting
                    if result < len(data):
                        raise Exception('failed to send all data')

                if remote in r:                             # remote socket(proxy) ready for reading
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break
                    data = self.decrypt(data)
                    result = send_all(sock, data)     # send to local socket(application)
                    if result < len(data):
                        raise Exception('failed to send all data')
        except Exception as e:
            logging.debug(e)
            logging.debug('local Accident!')
        finally:
            sock.close()
            remote.close()

    def encrypt(self, data):
        return myCrypt.encrypt(data)
    def decrypt(self, data):
        return myCrypt.decrypt(data)

    def send_encrypt(self, sock, data):
        enc = self.encrypt(data)
        dec = self.decrypt(enc)
        # logging.info('sending: ' + str(enc))
        sock.send(self.encrypt(data))

    def handle_old(self):
        try:
            sock = self.connection        # local socket [127.1:port]
            sock.recv(262)                # Sock5 Verification packet
            sock.send(b"\x05\x00")         # Sock5 Response: '0x05' Version 5; '0x00' NO AUTHENTICATION REQUIRED
            # After Authentication negotiation


            data = self.rfile.read(4)     # Forward request format: VER CMD RSV ATYP (4 bytes)
            mode = data[1]           # CMD == 0x01 (connect)
            if mode != 1:
                logging.warn('mode != 1')
                return
            addrtype = data[3]       # indicate destination address type
            addr_to_send = bytes([addrtype])
            if addrtype == 1:             # IPv4
                addr_ip = self.rfile.read(4)            # 4 bytes IPv4 address (big endian)
                addr = socket.inet_ntoa(addr_ip)
                addr_to_send += addr_ip
            elif addrtype == 3:           # FQDN (Fully Qualified Domain Name)

                # addr_len = self.rfile.read(10)           # Domain name's Length
                self.rfile.read(1) # tab char
                chunk = self.rfile.read(1)
                c = ''
                while c != b"\x00":
                    c = self.rfile.read(1)
                    chunk += c

                chunk = chunk[:-1]

                # addr = self.rfile.read(ord(addr_len))   # Followed by domain name(e.g. www.google.com)
                addr = chunk
                # addr_to_send += bytes([addr_len]) + bytes([addr])
            else:
                logging.warn('addr_type not support')
                # not support
                return
            addr_port = self.rfile.read(2)
            addr_to_send += addr_port                   # addr_to_send = ATYP + [Length] + dst addr/domain name + port
            port = struct.unpack('>H', addr_port)       # prase the big endian port number. Note: The result is a tuple even if it contains exactly one item.
            try:
                reply = b"\x05\x00\x00\x01"              # VER REP RSV ATYP
                reply += socket.inet_aton('0.0.0.0') + struct.pack(">H", 2222)  # listening on 2222 on all addresses of the machine, including the loopback(127.0.0.1)
                self.wfile.write(reply)                 # response packet
                # reply immediately
                if '-6' in sys.argv[1:]:                # IPv6 support
                    remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                else:
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)       # turn off Nagling
                remote.connect((SERVER, REMOTE_PORT))
                self.send_encrypt(remote, addr_to_send)      # encrypted
                logging.info('connecting %s:%d' % (addr, port[0]))
            except socket.error as e:
                logging.warn(e)
                return
            self.handle_tcp(sock, remote)
        except socket.error as e:
            logging.warn(e)

    def handle(self):
        try:
            sock = self.connection        # local socket [127.1:port]

            # follow SOCKS5 protocol

            sock.recv(262)                # Sock5 Verification packet
            sock.send(b"\x05\x00")         # Sock5 Response: '0x05' Version 5; '0x00' NO AUTHENTICATION REQUIRED
            # After Authentication negotiation



            data = self.connection.recv(4096)
            mode = data[1]           # CMD == 0x01 (connect)
            if mode != 1:
                logging.warn('mode != 1')
                return


            addrtype = data[3]       # indicate destination address type
            ptr = 4   # next to read index
            addr_to_send = bytes([addrtype])   # bytes only works for unsigned one byte number!!!!

            if addrtype == 1:             # IPv4
                ip_range = data[ptr:4+ptr]
                addr = socket.inet_ntoa(data[ptr:4+ptr])  # get dst addr

                addr_to_send += ip_range
                ptr += 4
            elif addrtype == 3:           # FQDN (Fully Qualified Domain Name)

                addr_len = int(data[ptr])          # Domain name's Length
                ptr += 1

                try:
                    addr = data[ptr:ptr+addr_len]
                except IndexError:
                    raise Exception('addr_len too long')

                ptr += addr_len
                # addr = self.rfile.read(ord(addr_len))   # Followed by domain name(e.g. www.google.com)

                addr_len = min(addr_len, 255)    # in case the url length is too long

                byte_len_ = bytes([addr_len])   # 0~255
                addr_to_send += byte_len_
                addr_to_send += addr
            else:
                logging.warn('addr_type not support')
                # not support
                return
            addr_port = data[ptr: 2+ptr]
            # addr_to_send += addr_port                   # addr_to_send = ATYP + [Length] + dst addr/domain name + port
            port = struct.unpack('>H', addr_port)       # prase the big endian port number. Note: The result is a tuple even if it contains exactly one item.
            addr_to_send += addr_port
            try:
                reply = b"\x05\x00\x00\x01"              # VER REP RSV ATYP
                reply += socket.inet_aton('0.0.0.0') + struct.pack(">H", 2222)  # listening on 2222 on all addresses of the machine, including the loopback(127.0.0.1)
                self.wfile.write(reply)                 # response packet
                # reply immediately
                if '-6' in sys.argv[1:]:                # IPv6 support
                    remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                else:
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)       # turn off Nagling
                remote.connect((SERVER, REMOTE_PORT))
                self.send_encrypt(remote, addr_to_send)      # encrypted
                logging.info('connecting %s:%d' % (addr, port[0]))
            except socket.error as e:
                logging.warn(e)
                return
            self.handle_tcp(sock, remote)
        except Exception as e:
            logging.warn(e)


if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')
    print('shadowsocks v0.9')

    with open('config.json', 'rb') as f:
        config = json.load(f)
    SERVER = config['server']
    REMOTE_PORT = config['server_port']
    PORT = config['local_port']
    KEY = config['password']

    optlist, args = getopt.getopt(sys.argv[1:], 's:p:k:l:')
    for key, value in optlist:
        if key == '-p':
            REMOTE_PORT = int(value)
        elif key == '-k':
            KEY = value
        elif key == '-l':
            PORT = int(value)
        elif key == '-s':
            SERVER = value

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    encrypt_table, decrypt_table = get_table(KEY)
    try:
        server = ThreadingTCPServer(('', PORT), Socks5Server)   # s.bind(('', 80)) specifies that the socket is reachable by any address the machine happens to have.
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error as e:
        logging.error(e)

