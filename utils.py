import select
import myCrypt
import logging
import socket

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(filename)s %(funcName)s %(lineno)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')


def encrypt(data):
    return myCrypt.encrypt(data)


def decrypt(data):
    return myCrypt.decrypt(data)


def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent


def send_all_arr(sock, message_queue):
    n = 0
    for data in message_queue:
        n += send_all(sock, data)
    message_queue.clear()
    return n


def handle_tcp(encrypt_sock, plain_sock, cid=0):
    """
    encrypt_sock: 加密sock
    plain_sock: 明文sock
    """
    trans_cnt = 0
    enc_read_cnt = enc_write_cnt = 0
    message_queue = {encrypt_sock: [], plain_sock: []}
    try:
        fdset = [encrypt_sock, plain_sock]
        while True:  # too long transaction may out of sync
            try:
                r, w, e = select.select(fdset, fdset, fdset)  # wait until ready
                for s in e:
                    if s == encrypt_sock:
                        send_all_arr(plain_sock, message_queue[plain_sock])
                        # plain_sock.close()
                    elif s == plain_sock:
                        send_all_arr(encrypt_sock, message_queue[encrypt_sock])
                        # encrypt_sock.close()
                    s.close()
                    break

                if encrypt_sock in r:
                    data = encrypt_sock.recv(40960)
                    if data == b'':
                        send_all_arr(plain_sock, message_queue[plain_sock])
                        break
                    enc_read_cnt += len(data)
                    data = decrypt(data)
                    message_queue[plain_sock].append(data)

                if plain_sock in r:
                    data = plain_sock.recv(4096)
                    if data == b'':
                        send_all_arr(encrypt_sock, message_queue[encrypt_sock])
                        break
                    data = encrypt(data)
                    message_queue[encrypt_sock].append(data)

                if encrypt_sock in w:
                    enc_write_cnt += send_all_arr(encrypt_sock, message_queue[encrypt_sock])

                if plain_sock in w:
                    send_all_arr(plain_sock, message_queue[plain_sock])

            except ConnectionResetError:
                logging.debug('connection has reset ' + str(plain_sock.getpeername()))
                break

            except ConnectionRefusedError:
                logging.debug('connection refused: ' + str(plain_sock.getpeername()))
                break

            except BrokenPipeError:
                logging.debug('broken pipe ' + str(plain_sock.getpeername()))
                break

    except Exception as esd:
        logging.error(esd)
    finally:
        encrypt_sock.close()
        plain_sock.close()
        logging.debug(f"[{cid}] enc_read:{enc_read_cnt}, enc_write:{enc_write_cnt}")
