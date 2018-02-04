import json
import logging
from binascii import b2a_hex, a2b_hex, b2a_base64, a2b_base64

SPLIT_STRING = b'inj\0x0yt\0x0gether'

class handshake:
    # returns byte type

    addr_type = 'ip'
    addr = ''
    port = '80'


    def __init__(self, addr_type='ip', addr='', port='80'):
        self.addr_type = addr_type
        self.addr = addr
        self.port = port


    def encode_protocol(self):
        data = {}
        # data['chatty'] = 'love' * 100
        data['type'] = 'handshake'
        data['version'] = 'v1'
        data['dst_addr'] = {'type': self.addr_type, 'addr':self.addr}
        data['dst_port'] = self.port
        rr = json.dumps(data, ensure_ascii=False, indent=True).encode('utf-8')
        return rr + SPLIT_STRING

    def decode_protocol(self, json_str):
        try:
            json_str = json_str.rsplit(SPLIT_STRING)[0].decode('utf-8')

            data = json.loads(json_str, encoding='utf-8')
            if data['type'] != 'handshake' or data['version'] != 'v1':
                logging.warning('Unknown format!')
                raise Exception('Unknown format!')
            self.addr_type = data['dst_addr']['type']
            self.addr = data['dst_addr']['addr']
            self.port = data['dst_port']
            return 'Done'
        except:
            return

class bytedata:
    # returns bytes type of data

    auth = ''
    raw_data = ''

    def __init__(self, auth='', raw_data=b''):
        self.auth = auth
        self.raw_data = raw_data


    def encode_protocol(self):
        data = {}
        data['auth'] = self.auth
        data['raw_data'] = b2a_hex(self.raw_data).decode('utf-8')
        return json.dumps(data, ensure_ascii=False, indent=True).encode('utf-8')


    def decode_protocol(self, json_str):
        try:
            data = json.loads(json_str.decode('utf-8'),encoding='utf-8')
            if data['auth'] != '':
                raise Exception('illegal user')

            self.auth = data['auth']
            # tmp =bytes(data['raw_data'], encoding='utf8')
            self.raw_data = a2b_hex(data['raw_data'].encode('utf-8'))
            return 'Done'

        except:
            return


