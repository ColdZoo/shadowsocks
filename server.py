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

    gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)
except ImportError:
    gevent = None
    print(sys.stderr, 'warning: gevent not found, using threading instead')

import socketserver
import os
import json
import handshake_protocol_v1 as hsp
from utils import *
import logging
import random

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

white_list = []
black_list = []


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):  # socket server polls to exit
    allow_reuse_address = True
    request_queue_size = 100000


class IllegalPacketException(Exception):
    pass


class Socks5Server(socketserver.StreamRequestHandler):

    def refuse_serve(self):
        self.wfile.write(b'0x15the_login_invalid_or_the_url_unreachable')

    def handle(self):  # override method
        try:
            sock = self.connection
            sock.settimeout(100)
            data = sock.recv(40960)
            dec_data = decrypt(data)

            try:
                obj = hsp.handshake()
                if obj.decode_protocol(dec_data) != 'Done':
                    raise IllegalPacketException('illegal packet recvd!')
                port = int(obj.port)
                addr = obj.addr

            except ConnectionRefusedError:
                logging.debug('connection refused')
                return

            except IllegalPacketException:
                logging.debug('refuse to serve!')
                self.refuse_serve()
                return

            # got all required information
            try:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                remote.settimeout(10)  # remote may timeout
                remote.connect((addr, port))  # connect to dst, may fail if blocked by gfw

                # generate session id
                session_id = 'sess' + str(random.randint(0, 1000))

                # if connect successfully, should sent a random message to unblock the client.
                send_all(sock, encrypt(session_id.encode(encoding="utf8")))

            except ConnectionRefusedError:
                logging.debug('connection refused: ' + str(addr))
                return
            except socket.timeout:
                logging.debug('TimeOut while connecting to: ' + str(addr))
                return
            except Exception as e_general:
                # Connection refused
                self.refuse_serve()
                if addr:
                    logging.warning(str(addr))
                logging.warning(e_general)
                return

            # do exchange

            handle_tcp(encrypt_sock=sock, plain_sock=remote, cid=session_id)
        except Exception as ex:
            logging.warning(ex)


def run_server(dst_server):
    dst_server.serve_forever()


if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')
    print('toysocks v1.1')

    with open('server_config.json', 'rb') as f:
        config = json.load(f)
    SERVER = config['server']
    PORT = config['server_port']

    # 启动代理server
    try:
        server = ThreadingTCPServer(('', PORT), Socks5Server)
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error as e:
        logging.error("[ABORTED!]")
        logging.error(e)
