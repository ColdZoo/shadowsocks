import select
import myCrypt
import logging
import time

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(filename)s %(funcName)s %(lineno)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')


def encrypt(data):
    return myCrypt.encrypt(data)


def decrypt(data):
    return myCrypt.decrypt(data)


def send_all(sock, data):
    flag = sock.sendall(data)
    if flag is None:
        return len(data)
    else:
        return 0


def send_all_arr(sock, message_queue):
    start_time = time.time()
    n = 0
    data_all = message_queue
    n += send_all(sock, data_all)
    elapsed_time = round(time.time() - start_time, 2)
    if elapsed_time > 1:
        logging.debug(f"time {elapsed_time}")
    return n


def handle_tcp(encrypt_sock, plain_sock, cid=0):
    """
    encrypt_sock: 加密sock
    plain_sock: 明文sock
    """
    enc_read_cnt = enc_write_cnt = 0
    message_queue = {encrypt_sock: b'', plain_sock: b''}
    try:
        fdset = [encrypt_sock, plain_sock]
        while True:  # too long transaction may out of sync
            try:
                r, w, e = select.select(fdset, [], [])  # wait until ready

                if encrypt_sock in r:
                    data = encrypt_sock.recv(40960)
                    if data == b'':
                        if plain_sock in w:
                            send_all_arr(plain_sock, message_queue[plain_sock])
                            message_queue[plain_sock] = b''
                        break
                    enc_read_cnt += len(data)
                    data = decrypt(data)
                    message_queue[plain_sock] += data

                    send_all_arr(plain_sock, message_queue[plain_sock])
                    message_queue[plain_sock] = b''

                if plain_sock in r:
                    data = plain_sock.recv(4096)
                    if data == b'':
                        if encrypt_sock in w:
                            send_all_arr(encrypt_sock, message_queue[encrypt_sock])
                            message_queue[encrypt_sock] = b''
                        break
                    data = encrypt(data)
                    message_queue[encrypt_sock] += data

                    enc_write_cnt += send_all_arr(encrypt_sock, message_queue[encrypt_sock])
                    message_queue[encrypt_sock] = b''

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
        logging.error(f"<{cid}>{esd}")
    finally:
        encrypt_sock.close()
        plain_sock.close()
        logging.debug(f"[{cid}] enc_read:{enc_read_cnt}, enc_write:{enc_write_cnt}")
