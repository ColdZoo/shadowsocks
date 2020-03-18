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
import random
import sys
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
import threading

try:
    import gevent
    import gevent.monkey

    gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)
except ImportError:
    gevent = None
    print(sys.stderr, 'warning: gevent not found, using threading instead')

# 用来执行心跳的线程
pulse_thread = None

WORKING_THREAD = 1


def pulse(ip, port):
    try:
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        remote.connect((ip, port))
        # logging.info(f"sending heartbeat to {ip}:{port}")
        send_all(remote, encrypt(hsp.handshake(addr='hello', port=str(port)).encode_protocol()))
    except ConnectionRefusedError:
        logging.warning(f"cannot talk to {ip}:{port}")
    except Exception as e:
        logging.warning(e)
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logging.warning(f"{exc_type}  {fname}  {exc_tb.tb_lineno}")

    global pulse_thread
    pulse_thread = threading.Timer(5, pulse, (ip, port))
    pulse_thread.start()


def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    request_queue_size = 100000


def encrypt(data):
    return myCrypt.encrypt(data)


def decrypt(data):
    return myCrypt.decrypt(data)


def send_encrypt(sock, data):
    sock.send(encrypt(data))


class Socks5Server(socketserver.StreamRequestHandler):
    def Mysplit(self, frame):  # return (head_rmnt, frame_list, tail_rmnt)
        if hsp.SPLIT_STRING in frame:
            frames = frame.split(hsp.SPLIT_STRING)
            if len(frames) == 2:
                frame_list = []
            elif len(frames) > 2:
                frame_list = frames[1:-1]
            return (frames[0], frame_list, frames[-1])

        else:
            return (frame, None, None)  # it's a whole frame

    def Mysend(self, sock, data):
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
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logging.warning(f"{exc_type}  {fname}  {exc_tb.tb_lineno}")

    ''' RequestHandlerClass Definition '''

    def handle_tcp(self, sock, remote, addr):
        try:
            fdset = [sock, remote]

            while True:
                try:
                    sock_buffer = None
                    remote_buffer = None
                    r, w, e = select.select(fdset, [], [])  # use select I/O multiplexing model
                    if remote in w and remote_buffer is not None:
                        send_all(remote, remote_buffer)
                        remote_buffer = None
                    if sock in w and sock_buffer is not None:
                        send_all(sock, sock_buffer)
                        sock_buffer = None
                    if sock in r:  # if local socket is ready for reading
                        data = sock.recv(65536)
                        if len(data) <= 0:  # received all data
                            logging.warning(f"sock 0 bytes: {len(data)}")
                            continue
                        remote_buffer = encrypt(data)
                    if remote in r:  # remote socket(proxy) ready for reading
                        data = remote.recv(65536)
                        # logging.info(f"[remote]got data from: {addr} length is {len(data)}")
                        if len(data) <= 0:
                            logging.warning(f"remote 0 bytes: {len(data)}")
                            continue
                        sock_buffer = decrypt(data)
                    if sock in e or remote in e:
                        sock.shutdown(socket.SHUT_RDWR)
                        remote.shutdown(socket.SHUT_RDWR)




                except ConnectionResetError:
                    logging.debug('connection has reset')
                    break

        except Exception as e:
            logging.debug(e)
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logging.warning(f"{exc_type}  {fname}  {exc_tb.tb_lineno}")

    def handle(self):
        try:
            remote = None
            addr = ""
            sock = self.connection  # local socket [127.1:port]
            sock.settimeout(15)
            # follow SOCKS5 protocol
            sock.recv(262)  # Sock5 Verification packet
            sock.send(b"\x05\x00")  # Sock5 Response: '0x05' Version 5; '0x00' NO AUTHENTICATION REQUIRED
            data = sock.recv(65536).strip()

            if data == b'':
                return

            mode = data[1]  # CMD == 0x01 (connect)
            data_to_send = {'type': 'handshake', 'version': 'v1'}
            if mode != 1:
                logging.warning('mode != 1')
                sock.close()
                return

            addrtype = data[3]  # indicate destination address type
            ptr = 4  # next to read index

            if addrtype == 1:  # IPv4
                ip_range = data[ptr:4 + ptr]
                addr = socket.inet_ntoa(data[ptr:4 + ptr])  # get dst addr
                str_addr = addr
                ptr += 4
            elif addrtype == 3:  # FQDN (Fully Qualified Domain Name)
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
            data_to_send['dst_port'] = port[0]
            try:
                if '-6' in sys.argv[1:]:  # IPv6 support
                    remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                else:
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # turn off Nagling
                remote.settimeout(20)

                # 随机挑选一个REMOTE_PORT 进行连接
                dst_port = random.randint(0, WORKING_THREAD - 1) + 10 + REMOTE_PORT
                logging.info(f"--------------random port is: {dst_port}")
                remote.connect((SERVER, dst_port))

                # connected to the server, should complete authentication and after the peer has established connection
                # to host.
                # then should let browser send other data

                m = hsp.handshake(addr=str_addr, port=str(port[0]))
                msg = m.encode_protocol()
                send_encrypt(remote, msg)  # encrypted handshake
                # 这里会阻塞
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
                logging.info('requested: %s:%d' % (str_addr, port[0]))

            except ConnectionRefusedError:
                logging.warning("cannnot talk to server")

            except socket.error as es:
                logging.warning(es)
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                logging.warning(f"{exc_type}  {fname}  {exc_tb.tb_lineno}")

                reply = b"\x05\x04\x00\x01"  # host unreachable
                self.wfile.write(reply)  # response packet
                sock.close()
                return

            self.handle_tcp(sock, remote, str_addr)

        except Exception as es:
            logging.warning(es)
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logging.warning(f"{exc_type}  {fname}  {exc_tb.tb_lineno}")
        finally:
            if sock is not None:
                sock.close()
            if remote is not None:
                remote.close()
            logging.info(f'connection closed.{addr}')


if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')
    print('toysocks v1.0')

    FILE_NAME = 'config.json'

    optlist, args = getopt.getopt(sys.argv[1:], 's:p:k:l:f:')
    for key, value in optlist:
        if key == '-p':
            REMOTE_PORT = int(value)
        elif key == '-k':
            KEY = value
        elif key == '-l':
            PORT = int(value)
        elif key == '-s':
            SERVER = value
        elif key == "-f":
            FILE_NAME = value

    print("Config file is: " + FILE_NAME)
    with open(FILE_NAME, 'rb') as f:
        config = json.load(f)
    SERVER = config['server']
    REMOTE_PORT = int(config['server_port'])
    PORT = int(config['local_port'])
    KEY = config['password']

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(funcName)s %(lineno)d %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    # 启动心跳任务
    pulse(SERVER, REMOTE_PORT + 1)

    try:
        server = ThreadingTCPServer(('0.0.0.0', PORT), Socks5Server)
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error as e:
        logging.error(e)
