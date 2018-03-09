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

SERVER = ''
REMOTE_PORT = ''


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


class MITMServer(socketserver.StreamRequestHandler):

    def handle(self):  # override method
        try:
            sock = self.connection

            # got all required information
            try:

                logging.info('connecting %s:%d' % (SERVER, REMOTE_PORT))
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


                remote.settimeout(10)
                remote.connect((SERVER, REMOTE_PORT))         # connect to dst, may fail if blocked by gfw

            except Exception as e:
                logging.warn(e)
                return

            # do mitm

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

                            result = send_all(remote, data)
                            if result < len(data):
                                raise Exception('failed to send all data')

                        if remote in r:
                            data = remote.recv(4096)
                            if len(data) <= 0:
                                break

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

        except socket.error as e:
            logging.warn(e)


if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')
    print('toysocks-mitm-server v0.10')

    with open('mitm.json', 'rb') as f:
        config = json.load(f)
    SERVER = config['remote']
    REMOTE_PORT = config['remote_port']
    PORT = config['local_port']
    IP = config['local_ip']

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
        server = ThreadingTCPServer((IP, PORT), MITMServer)   # s.bind(('', 80)) specifies that the socket is reachable by any address the machine happens to have.
        logging.info("starting server at port %d ..." % PORT)
        server.serve_forever()
    except socket.error as e:
        logging.error(e)