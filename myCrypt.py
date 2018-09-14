from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex, b2a_base64, a2b_base64
import logging
import base64

class prpcrypt():
    def __init__(self, key):
        self.key = key
        self.mode = AES.MODE_CFB

    # 加密函数，如果text不是16的倍数【加密文本text必须为16的倍数！】，那就补足为16的倍数
    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.key)
        # 这里密钥key 长度必须为16（AES-128）、24（AES-192）、或32（AES-256）Bytes 长度.目前AES-128足够用
        length = 32
        count = len(text)
        if (count % length != 0):
            add = length - (count % length)
        else:
            add = 0
        text = text + (b'\0' * add)
        self.ciphertext = cryptor.encrypt(text)
        # base64.encode(self.ciphertext)
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        # return b2a_base64(self.ciphertext)
        return str(base64.encodebytes(self.ciphertext), encoding='utf-8')

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.key)
        plain_text = cryptor.decrypt(base64.decodebytes(text.encode(encoding='utf-8')))
        # plain_text = cryptor.decrypt(text)
        return plain_text.rstrip(b'\0')



pc = prpcrypt(b'keyskeyskeyskeys')  # 初始化密钥
pg = prpcrypt(b'uiwoejlkwhuyjeoi')

# todo: encrypt stack


def encrypt(data):
    return ez_encrypt(data)
    # tmp = pc.encrypt(data)
    # return pg.encrypt(tmp)


def decrypt(data):
    return ez_decrypt(data)
    # tmp = pg.decrypt(data)
    # return pc.decrypt(tmp)


def ez_encrypt(data):
    if isinstance(data, bytes):
        tmp = bytes([p ^ 0x15 for p in data])
    else:
        logging.warning('illegal format')
        return
    return tmp


def ez_decrypt(data):
    return ez_encrypt(data)


