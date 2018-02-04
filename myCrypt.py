from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex, b2a_base64, a2b_base64


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
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为16进制字符串
        # return b2a_base64(self.ciphertext)
        return self.ciphertext

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.key)
        # plain_text = cryptor.decrypt(a2b_base64(text))
        plain_text = cryptor.decrypt(text)
        return plain_text.rstrip(b'\0')



pc = prpcrypt(b'keyskeyskeyskeys')  # 初始化密钥
pg = prpcrypt(b'uiwoejlkwhuyjeoi')


def encrypt(data):
    return ez_encrypt(data)
    tmp = pc.encrypt(data)
    return pg.encrypt(tmp)


def decrypt(data):
    return ez_decrypt(data)
    tmp = pg.decrypt(data)
    return pc.decrypt(tmp)


def ez_encrypt(data):
    tmp = bytes([p ^ 0x10 for p in data])
    return tmp

def ez_decrypt(data):
    return ez_encrypt(data)

if __name__ == '__main__':
    e = ez_encrypt(b'\x03\x0ewww.google.com\x01\xbb')
    d = ez_decrypt(e)
    print(d)
    e = encrypt(b"00000000000000000000000000")
    d = decrypt(e)
    print(d)
    e = ez_encrypt(bytes([0b0, 0b1, 0b1]))
    d = ez_decrypt(e)
    print(d)
