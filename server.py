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


#
# from gevent import monkey
# monkey.patch_all()
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

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):  # socket server polls to exit
    allow_reuse_address = True


class Socks5Server(socketserver.StreamRequestHandler):


    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])  # wait until ready
                if sock in r:
                    data = sock.recv(4096)
                    if len(data) <= 0:
                        break
                    # logging.info('send_to_remote: ' + str(data))
                    data = self.decrypt(data)
                    result = send_all(remote, data)
                    if result < len(data):
                        raise Exception('failed to send all data')
                if remote in r:
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break
                    # logging.info('send_to_local: ' + str(data))
                    data = self.encrypt(data)
                    result = send_all(sock, data)
                    if result < len(data):
                        raise Exception('failed to send all data')

        except Exception as e:
            logging.debug("Accidentally exited")
            logging.debug(e)

        finally:
            sock.close()
            remote.close()


    def encrypt(self, data):
        return myCrypt.encrypt(data)
    def decrypt(self, data):
        return myCrypt.decrypt(data)

    def handle(self):  # override method
        try:
            sock = self.connection
            data = self.connection.recv(4096)
            dec_data = self.decrypt(data)

            # data = dec_data


            # # follow self defined protocol
            # data_pointer = 0
            #
            # addrtype = data[data_pointer]      # receive addr type, unicode
            # if addrtype == 1: #ipv4
            #     addr = socket.inet_ntoa(data[1:4])   # get dst addr
            #     data_pointer = 5 # point to the port
            # elif addrtype == 3: #domain name or ipv6
            #     # addr = self.decrypt(
            #     #     self.rfile.read(ord(self.decrypt(sock.recv(1)))))       # read 1 byte of len, then get 'len' bytes name
            #     addr_len = data[1]
            #     addr = data[2:2+addr_len]
            #     addr = addr.decode('utf-8')
            #     data_pointer = 2+addr_len
            # else:
            #     # not support
            #     logging.warn('addr_type not support')
            #     return
            #
            #
            # # '>H' means big endian, unsigned short
            # port_range = data[data_pointer:data_pointer+2]
            # data_pointer += 2                        # already got all the information we need, if it has more byte, should send them to the remote
            # port = struct.unpack('>H', port_range)

            try:
                obj = hsp.handshake()
                if obj.decode_protocol(dec_data) != 'Done':
                    raise Exception('illegal packet recvd!')
                port = (int(obj.port), 0)
                addr = obj.addr
            except Exception as e:
                logging.warning(e)
                return


            # got all required information
            try:


                logging.info('connecting %s:%d' % (addr, port[0]))
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


                remote.settimeout(3)
                remote.connect((addr, port[0]))         # connect to dst, may fail if blocked by gfw

                remaint = obj.remaint
                # remaint = data[data_pointer:]
                if len(remaint) > 0:
                    logging.debug('sending_remaint_: ' + str(len(remaint)))
                    send_all(remote, remaint)


            except Exception as e:
                # Connection refused
                logging.warn(e)
                # send empty message to browser
                return

            # do exchange
            self.handle_tcp(sock, remote)
        except socket.error as e:
            logging.warn(e)

if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')

    print('shadowsocks v0.9')

    with open('config.json', 'rb') as f:
        config = json.load(f)

    SERVER = config['server']
    PORT = config['server_port']
    KEY = config['password']
    KEY = KEY.encode('utf-8')

    optlist, args = getopt.getopt(sys.argv[1:], 'p:k:')
    for key, value in optlist:
        if key == '-p':
            PORT = int(value)
        elif key == '-k':
            KEY = value

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    # encrypt_table,decrypt_table = get_table(KEY)
    # decrypt_table = str.maketrans(encrypt_table, str.maketrans('', ''))


    if '-6' in sys.argv[1:]:
        ThreadingTCPServer.address_family = socket.AF_INET6
    try:
        server = ThreadingTCPServer(('', PORT), Socks5Server)
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error as e:
        logging.error(e)

