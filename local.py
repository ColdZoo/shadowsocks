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

try:
    import gevent, gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)
except ImportError:
    gevent = None
    print(sys.stderr, 'warning: gevent not found, using threading instead')


import socket
import select
import socketserver
import struct
import os
import json
import logging
import getopt
import myCrypt
import handshake_protocol_v1 as hsp




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
    request_queue_size = 1000


class Socks5Server(socketserver.StreamRequestHandler):


    def Mysplit(self, frame):  # return (head_rmnt, frame_list, tail_rmnt)
        if hsp.SPLIT_STRING in frame:
            frames = frame.split(hsp.SPLIT_STRING)
            if len(frames) == 2:
                frame_list = []
            elif len(frames) >2:
                frame_list = frames[1:-1]
            return (frames[0], frame_list, frames[-1])

        else:
            return (frame, None, None)  # it's a whole frame


    def Mysend(self,sock, data):
        if not isinstance(data, bytes):
            pass
        if data == b'':
            return

        n = hsp.bytedata()
        try:
            if n.decode_protocol(proto_byte=data) != 'Done':
                logging.warning('Illegal packet, skipped')
                return

            result = send_all(sock, n.raw_data)  # send to local socket(application)
            if result < len(n.raw_data):
                raise Exception('failed to send all data')

        except Exception as e:
            logging.warning(e)


    ''' RequesHandlerClass Definition '''
    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]

            remote_remaint = b''

            while True:
                try:
                    r, w, e = select.select(fdset, [], [])      # use select I/O multiplexing model
                    if sock in r:                               # if local socket is ready for reading

                        data = sock.recv(4096)
                        if len(data) <= 0:                      # received all data
                            break

                        m = hsp.bytedata(raw_data=data)

                        data = self.encrypt(m.encode_protocol())
                        result = send_all(remote, data)   # send data after encrypting

                        if result < len(data):
                            raise Exception('failed to send all data')

                    if remote in r:                             # remote socket(proxy) ready for reading
                        data = remote.recv(4096)
                        if len(data) <= 0:
                            break

                        data = self.decrypt(data)
                        head_rmnt, frame_list, tail_rmnt = self.Mysplit(data)

                        if hsp.SPLIT_STRING in data:
                            frame_tmp = remote_remaint + head_rmnt
                            for f in frame_tmp.split(hsp.SPLIT_STRING):
                                self.Mysend(sock, f)

                            for frame in frame_list:
                                self.Mysend(sock, frame)
                            remote_remaint = tail_rmnt


                        else:
                            remote_remaint += data
                except ConnectionResetError:
                    logging.debug('connection has reset')
                    continue


        except Exception as e:
            logging.debug(e)
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


    def handle(self):
        try:
            sock = self.connection        # local socket [127.1:port]

            # follow SOCKS5 protocol

            sock.recv(262)                # Sock5 Verification packet
            sock.send(b"\x05\x00")         # Sock5 Response: '0x05' Version 5; '0x00' NO AUTHENTICATION REQUIRED

            data = sock.recv(4096).strip()

            if data == b'':
                return

            mode = data[1]           # CMD == 0x01 (connect)
            data_to_send = {}
            data_to_send['type'] = 'handshake'
            data_to_send['version'] = 'v1'
            if mode != 1:
                logging.warn('mode != 1')
                sock.close()
                return


            addrtype = data[3]       # indicate destination address type
            ptr = 4   # next to read index


            if addrtype == 1:             # IPv4
                ip_range = data[ptr:4+ptr]
                addr = socket.inet_ntoa(data[ptr:4+ptr])  # get dst addr

                ptr += 4
                data_to_send['dst_addr'] = {'type':'ip', 'addr': addr.decode('utf-8')}

            elif addrtype == 3:           # FQDN (Fully Qualified Domain Name)

                addr_len = int(data[ptr])          # Domain name's Length
                ptr += 1

                try:
                    addr = data[ptr:ptr+addr_len]

                except:
                    raise Exception('addr_len too long')

                ptr += addr_len

                addr_len = min(addr_len, 255)    # in case the url length is too long

                byte_len_ = bytes([addr_len])   # 0~255

                data_to_send['dst_addr'] = {'type':'url', 'addr':addr.decode('utf-8')}

            else:
                logging.warn('addr_type not support')
                sock.close()
                # not support
                return
            addr_port = data[ptr: 2+ptr]
            # addr_to_send += addr_port                   # addr_to_send = ATYP + [Length] + dst addr/domain name + port
            port = struct.unpack('>H', addr_port)       # prase the big endian port number. Note: The result is a tuple even if it contains exactly one item.

            data_to_send['dst_port'] = port[0]
            try:

                # reply immediately
                if '-6' in sys.argv[1:]:                # IPv6 support
                    remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                else:
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)       # turn off Nagling
                remote.connect((SERVER, REMOTE_PORT))

                # connected to the server, should complete authentication and after the peer has established connection to host.
                # then should let browser send other data

                m = hsp.handshake(addr=addr.decode('utf-8'), port=str(port[0]))
                msg = m.encode_protocol()
                self.send_encrypt(remote, msg)  # encrypted handshake

                confirm_msg = remote.recv(4096)

                if b'0x15the_login_invalid_or_the_url_unreachable' == confirm_msg:
                    logging.error('Error: 1. The url is unreachable for the proxy 2. Or encrypt method mismatch.')
                    sock.close()
                    return


                # tell the browser we are ready to proxy for you.

                reply = b"\x05\x00\x00\x01"  # VER REP RSV ATYP
                # socks5 protocol needs this. its a must
                reply += socket.inet_aton('192.168.34.34') + struct.pack(">H", 1030)
                self.wfile.write(reply)  # response packet




                logging.info('requested: %s:%d' % (addr.decode('utf-8'), port[0]))

            except socket.error as e:
                reply = b"\x05\x04\x00\x01" # host unreachable
                self.wfile.write(reply)  # response packet
                logging.warn(e)
                sock.close()
                return


            self.handle_tcp(sock, remote)



        except Exception as e:
            logging.warn(data)
            logging.warn(e)


if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')
    print('toysocks v0.9')

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

    try:
        server = ThreadingTCPServer(('', PORT), Socks5Server)   # s.bind(('', 80)) specifies that the socket is reachable by any address the machine happens to have.
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error as e:
        logging.error(e)

