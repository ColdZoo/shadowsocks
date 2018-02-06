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


    def Mysend(self, sock, data):
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


    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            sock_remaint = b''
            while True:
                try:

                    r, w, e = select.select(fdset, [], [])  # wait until ready
                    if sock in r:
                        data = sock.recv(4096)
                        if len(data) <= 0:
                            break

                        data = self.decrypt(data)

                        head_rmnt, frame_list, tail_rmnt = self.Mysplit(data)

                        if hsp.SPLIT_STRING in data:
                            frame = sock_remaint + head_rmnt
                            for f in frame.split(hsp.SPLIT_STRING):
                                self.Mysend(remote, f)

                            for frame in frame_list:
                                self.Mysend(remote, frame)
                            sock_remaint = tail_rmnt


                        else:
                            sock_remaint += data  # very long frame


                    if remote in r:
                        data = remote.recv(4096)
                        if len(data) <= 0:
                            break

                        m = hsp.bytedata(raw_data=data)
                        data = self.encrypt(m.encode_protocol())


                        result = send_all(sock, data)
                        if result < len(data):
                            raise Exception('failed to send all data')

                except ConnectionResetError:
                    logging.debug('connection has reset')


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

    def refuse_serve(self):
        self.wfile.write(b'0x15the_login_invalid_or_the_url_unreachable')

    def handle(self):  # override method
        try:
            sock = self.connection
            data = self.connection.recv(4096)
            dec_data = self.decrypt(data)

            try:
                obj = hsp.handshake()
                if obj.decode_protocol(dec_data) != 'Done':
                    raise Exception('illegal packet recvd!')
                port = (int(obj.port), 0)
                addr = obj.addr
            except Exception as e:
                self.refuse_serve()
                logging.warning(e)
                return


            # got all required information
            try:



                logging.info('connecting %s:%d' % (addr, port[0]))
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


                remote.settimeout(10)
                remote.connect((addr, port[0]))         # connect to dst, may fail if blocked by gfw

                # if connect successfully, should sent a random message to unblock the client.
                send_all(sock, self.encrypt(hsp.handshake(addr='www.mars.mars', port='76767').encode_protocol()))


                # due to the client will block until we reply, there should not have remaint bytes

                # remaint = obj.remaint
                # if len(remaint) > 0:
                #     logging.debug('sending_remaint_: ' + str(len(remaint)))
                #     data_to_send = hsp.bytedata(raw_data=remaint).encode_protocol()
                #     send_all(remote, self.encrypt(data_to_send))



            except Exception as e:
                # Connection refused
                self.refuse_serve()
                logging.warn(e)
                # send empty message to browser
                return

            # do exchange
            self.handle_tcp(sock, remote)
        except socket.error as e:
            logging.warn(e)



if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')

    print('toysocks v0.9')

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


    if '-6' in sys.argv[1:]:
        ThreadingTCPServer.address_family = socket.AF_INET6
    try:
        server = ThreadingTCPServer(('', PORT), Socks5Server)
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error as e:
        logging.error(e)

