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

    gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)
except ImportError:
    gevent = None
    print(sys.stderr, 'warning: gevent not found, using threading instead')

import socket
import select
import socketserver
import os
import json
import logging
import getopt
import myCrypt

import handshake_protocol_v1 as hsp
import threading

white_list = []
black_list = []

REMOTE_SOCKET_COUNT = 0
LOCAL_SOCKET_COUNT = 0
HEARTBEAT_SOCKET_COUNT = 0

monitor_thread = None


def monitor():
    try:
        logging.info(
            f"#Sockets: Remote:{REMOTE_SOCKET_COUNT} Local:{LOCAL_SOCKET_COUNT} Heart:{HEARTBEAT_SOCKET_COUNT}")
    except Exception as e:
        logging.warning(e)
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logging.warning(f"{exc_type}  {fname}  {exc_tb.tb_lineno}")

    global monitor_thread
    monitor_thread = threading.Timer(5, monitor)
    monitor_thread.start()


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
    request_queue_size = 100000


def Mysplit(frame):  # return (head_rmnt, frame_list, tail_rmnt)
    if hsp.SPLIT_STRING in frame:
        frames = frame.split(hsp.SPLIT_STRING)
        if len(frames) == 2:
            frame_list = []
        elif len(frames) > 2:
            frame_list = frames[1:-1]
        return (frames[0], frame_list, frames[-1])

    else:
        return (frame, None, None)  # it's a whole frame


def Mysend(sock, data):
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


def encrypt(data):
    return myCrypt.encrypt(data)


def decrypt(data):
    return myCrypt.decrypt(data)


class HeartBeatServer(socketserver.StreamRequestHandler):
    def handle(self):
        global HEARTBEAT_SOCKET_COUNT
        sock = self.connection
        HEARTBEAT_SOCKET_COUNT += 1
        sock.settimeout(10)
        try:
            data = sock.recv(4096)
        except TimeoutError:
            logging.warning(f"HeartBeat Timed out")
        dec_data = decrypt(data)
        obj = hsp.handshake()
        peer_ip, port = sock.getpeername()
        # 收到请求时如果是白名单中的ip, 则不需要再校验
        if peer_ip not in white_list:
            logging.info(f"received heartbeat from {peer_ip}, white_list:{white_list}, black_list:{black_list}")
            # 收到请求若是黑名单中的, 则直接拒绝
            if peer_ip in black_list:
                logging.info(f"rejected black listed heartbeat {peer_ip}")
                raise Exception(f"rejected black listed heartbeat {peer_ip}")
            else:
                try:
                    if obj.decode_protocol(dec_data) != 'Done':
                        # 加入黑名单
                        black_list.append(peer_ip)
                        logging.info(
                            f"after {peer_ip}, white_list:{white_list}, black_list:{black_list}")
                    else:
                        # 加入白名单
                        white_list.append(peer_ip)
                        if peer_ip in black_list:
                            black_list.remove(peer_ip)
                        logging.info(f"after {peer_ip}, white_list:{white_list}, black_list:{black_list}")
                except Exception as e:
                    logging.error(e)
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    logging.warning(f"{exc_type}  {fname}  {exc_tb.tb_lineno}")
                    pass
        sock.close()
        HEARTBEAT_SOCKET_COUNT -= 1


class Socks5Server(socketserver.StreamRequestHandler):

    def handle_tcp(self, sock, remote, addr):
        global REMOTE_SOCKET_COUNT, LOCAL_SOCKET_COUNT
        try:
            fdset = [sock, remote]
            # sock: 服务端
            # remote: web服务器
            while True:
                try:
                    r, w, e = select.select(fdset, [], [])  # wait until ready
                    if sock in r:
                        data = sock.recv(65536)
                        # logging.info(f"got data from client: {addr} length: {len(data)}")
                        if len(data) <= 0:
                            # logging.error(f"local recvd bytes error!{len(data)}")
                            break

                        data = decrypt(data)
                        send_all(remote, data)

                    if remote in r:
                        data = remote.recv(65536)
                        # logging.info(f"got data from web server: {addr} length:{len(data)}")
                        if len(data) <= 0:
                            # logging.error(f"remote recvd bytes error!{len(data)}")
                            break

                        data = encrypt(data)

                        result = send_all(sock, data)
                        if result < len(data):
                            raise Exception('failed to send all data')

                except ConnectionResetError:
                    logging.debug('connection has reset ' + addr)
                    break

                except ConnectionRefusedError:
                    logging.debug('connection refused: ' + addr)
                    break

                except BrokenPipeError:
                    logging.debug('broken pipe ' + addr)
                    break

                except socket.error:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    logging.warning(f"{exc_type}  {fname}  {exc_tb.tb_lineno}")
                    break

        except Exception as e:
            logging.debug("Transfer Accidentally exited")
            logging.debug(e)
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logging.warning(f"{exc_type}  {fname}  {exc_tb.tb_lineno}")

    def refuse_serve(self):
        self.wfile.write(b'0x15the_login_invalid_or_the_url_unreachable')

    def handle(self):  # override method
        global REMOTE_SOCKET_COUNT, LOCAL_SOCKET_COUNT
        try:
            sock = self.connection
            sock.settimeout(15)
            data = sock.recv(4096)
            LOCAL_SOCKET_COUNT += 1
            dec_data = decrypt(data)
            remote = None
            addr = None

            peer_ip, peer_port = sock.getpeername()
            if peer_ip in black_list or peer_ip not in white_list:
                # 若已经在黑名单上, 或者不在白名单里, 则直接拒绝代理
                logging.warning(f"[Socks5Server]rejected a request from {peer_ip}")
                raise Exception('illegal packet recvd!')
            try:
                obj = hsp.handshake()
                if obj.decode_protocol(dec_data) != 'Done':
                    raise Exception('illegal packet recvd!')
                port = int(obj.port)
                addr = obj.addr

            except Exception as e:
                self.refuse_serve()
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                logging.warning(f"{exc_type}  {fname}  {exc_tb.tb_lineno}")
                raise Exception("malformed handshake!")

            # got all required information
            try:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                REMOTE_SOCKET_COUNT += 1
                remote.settimeout(50)
                remote.connect((addr, port))  # connect to dst, may fail if blocked by gfw

                # if connect successfully, should sent a random message to unblock the client.
                send_all(sock, encrypt(hsp.handshake(addr=addr, port=str(port)).encode_protocol()))
                # do exchange
                self.handle_tcp(sock, remote, str(addr))
            except ConnectionRefusedError:
                logging.debug('connection refused: ' + str(addr))
            except socket.timeout:
                logging.debug('TimeOut while connecting to: ' + str(addr))
            except Exception as e:
                self.refuse_serve()
                logging.warning(str(addr))
                logging.warning(e)
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                logging.warning(f"{exc_type}  {fname}  {exc_tb.tb_lineno}")
                # send empty message to browser
        except Exception as e:
            logging.warning(e)
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logging.warning(f"{exc_type}  {fname}  {exc_tb.tb_lineno}")
        finally:
            if sock is not None:
                sock.close()
                LOCAL_SOCKET_COUNT -= 1
            if remote is not None:
                remote.close()
                REMOTE_SOCKET_COUNT -= 1
            if addr is not None:
                logging.info(f'released resource! {addr}')


def run_server(dst_server):
    dst_server.serve_forever()


if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')
    print('toysocks v1.0')

    with open('server_config.json', 'rb') as f:
        config = json.load(f)

    SERVER = config['server']
    PORT = config['server_port']

    optlist, args = getopt.getopt(sys.argv[1:], 'p:k:')
    for key, value in optlist:
        if key == '-p':
            PORT = int(value)

    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(funcName)s %(lineno)d %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    if '-6' in sys.argv[1:]:
        ThreadingTCPServer.address_family = socket.AF_INET6

    # 启动心跳server
    pulse_server = ThreadingTCPServer(('', PORT + 1), HeartBeatServer)
    logging.info(f'starting heart beat server at port {PORT + 1}')

    pulse_server_thread = threading.Thread(target=run_server, args=(pulse_server,))
    pulse_server_thread.start()

    # 启动监控
    monitor()

    # 启动代理server
    worker_count = 5
    workers = []

    for i in range(0, worker_count):
        worker_server = ThreadingTCPServer(('', PORT + 10 + i), Socks5Server)
        logging.info(f"starting server at port {PORT + 10 + i} ...")
        worker_thread = threading.Thread(target=run_server, args=(worker_server,))
        worker_thread.start()
        workers.append(worker_thread)

    try:
        server = ThreadingTCPServer(('', PORT), Socks5Server)
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error as e:
        logging.error("[ABORTED!]")
        logging.error(e)
