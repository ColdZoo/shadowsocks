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
import socketserver
import struct
import os
import json
import handshake_protocol_v1 as hsp
from utils import *

BLK_CNT = 0

try:
    import gevent
    import gevent.monkey

    gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)
except ImportError:
    gevent = None
    print(sys.stderr, 'warning: gevent not found, using threading instead')


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    request_queue_size = 100000


def send_encrypt(sock, data):
    sock.send(encrypt(data))


class Socks5Server(socketserver.StreamRequestHandler):
    """ RequestHandlerClass Definition """

    def handle(self):
        global BLK_CNT
        try:
            sock = self.connection  # local socket [127.1:port]

            # SOCKS5 protocol
            sock.recv(262)  # Sock5 Verification packet
            sock.send(b"\x05\x00")  # Sock5 Response: '0x05' Version 5; '0x00' NO AUTHENTICATION REQUIRED
            data = sock.recv(1024).strip()
            if data == b'':
                return

            mode = data[1]  # CMD == 0x01 (connect)
            if mode != 1:
                logging.warning('mode != 1')
                sock.close()
                return

            addrtype = data[3]  # indicate destination address type
            ptr = 4  # next to read index

            if addrtype == 1:  # IPv4
                addr = socket.inet_ntoa(data[ptr:4 + ptr])  # get dst addr
                str_addr = addr
                ptr += 4
            elif addrtype == 3:  # (Fully Qualified Domain Name)
                addr_len = int(data[ptr])  # Domain name's Length
                ptr += 1
                addr = data[ptr:ptr + addr_len]
                str_addr = addr.decode('utf-8')
                ptr += addr_len
            else:
                # not support
                logging.warning('addr_type not support')
                sock.close()
                return
            addr_port = data[ptr: 2 + ptr]
            # Parse the big endian port number. Note: The result is a tuple even if it contains exactly one item.
            port = struct.unpack('>H', addr_port)
            try:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.settimeout(100)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # turn off Nagling
                remote.connect((SERVER, REMOTE_PORT))

                # connected to the server, should complete authentication and after the peer has established connection
                # to host.
                # then should let browser send other data

                m = hsp.handshake(addr=str_addr, port=str(port[0]))
                msg = m.encode_protocol()
                send_encrypt(remote, msg)  # encrypted handshake
                BLK_CNT += 1
                logging.debug(f"BLK-CNT: {BLK_CNT}")
                confirm_msg = remote.recv(450)

                if b'0x15the_login_invalid_or_the_url_unreachable' == confirm_msg:
                    logging.error('server refused to serve for us!')
                    return

                # if server closed socket directly
                if confirm_msg == b'':
                    raise socket.error("server refused")

                session_id = decrypt(confirm_msg).decode(encoding="utf8")
                BLK_CNT -= 1

                logging.info(f'accepted {str_addr} with {session_id}')

                # tell the browser we are ready to proxy for you.
                reply = b"\x05\x00\x00\x01"  # VER REP RSV ATYP
                # socks5 protocol needs this.
                reply += socket.inet_aton('192.168.34.34') + struct.pack(">H", 1030)
                self.wfile.write(reply)  # response packet

            except socket.error as es:
                reply = b"\x05\x04\x00\x01"  # host unreachable
                self.wfile.write(reply)  # response packet
                logging.warning(es)
                return

            handle_tcp(encrypt_sock=remote, plain_sock=sock, cid=session_id)
            logging.debug(f"BLK-CNT: {BLK_CNT}")

        except Exception as es:
            logging.warning(es.__traceback__.tb_lineno)  # 打印行号
            logging.warning(es)


if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')
    print('toysocks v1.1')
    FILE_NAME = 'config.json'
    # FILE_NAME = 'config_local.json'
    logging.info("Config file is: " + FILE_NAME)
    with open(FILE_NAME, 'rb') as f:
        config = json.load(f)
    SERVER = config['server']
    REMOTE_PORT = int(config['server_port'])
    PORT = int(config['local_port'])

    try:
        server = ThreadingTCPServer(('0.0.0.0', PORT), Socks5Server)
        logging.info(f"sock5 listening at port {PORT} ...")
        server.serve_forever()
    except socket.error as e:
        logging.error(e)
