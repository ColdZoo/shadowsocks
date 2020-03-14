import logging


def encrypt(data):
    return ez_encrypt(data)


def decrypt(data):
    return ez_decrypt(data)


def ez_encrypt(data):
    if isinstance(data, bytes):
        tmp = bytes([p ^ 0x15 for p in data])
    else:
        logging.warning('illegal format')
        return
    return tmp


def ez_decrypt(data):
    return ez_encrypt(data)
