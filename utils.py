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


def handle_tcp(encrypt_sock, plain_sock, cid=0):
    """
    encrypt_sock: 加密sock
    plain_sock: 明文sock
    """
    trans_cnt = 0
    enc_read_cnt = enc_write_cnt = 0
    try:
        fdset = [encrypt_sock, plain_sock]
        while trans_cnt < 50000:  # too long transaction may out of sync
            try:
                r, w, e = select.select(fdset, [], [])  # wait until ready
                trans_cnt += 1
                if encrypt_sock in r:
                    data = encrypt_sock.recv(40960)
                    if len(data) <= 0:
                        break
                    enc_read_cnt += len(data)
                    data = decrypt(data)
                    send_all(plain_sock, data)

                if plain_sock in r:
                    data = plain_sock.recv(40960)
                    if len(data) <= 0:
                        break
                    data = encrypt(data)
                    n = send_all(encrypt_sock, data)
                    enc_write_cnt += n

            except ConnectionResetError:
                logging.debug('connection has reset ' + str(plain_sock.getpeername()))
                break

            except ConnectionRefusedError:
                logging.debug('connection refused: ' + str(plain_sock.getpeername()))
                break

            except BrokenPipeError:
                logging.debug('broken pipe ' + str(plain_sock.getpeername()))
                break

            # except socket.error as socket_err:
            #     logging.error(socket_err)
            #     logging.error(str(plain_sock.getpeername()))
            #     break

    except Exception as esd:
        logging.error(esd)
    finally:
        encrypt_sock.close()
        plain_sock.close()
        logging.debug(f"[{cid}] trans_cnt:{trans_cnt}, enc_read:{enc_read_cnt}, enc_write:{enc_write_cnt}")
