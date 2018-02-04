import handshake_protocol_v1 as hsp
m = hsp.handshake('ip', '1.1.1.1', '8080')
n = hsp.handshake('url', 'www.baidu.com', '8080')
u = hsp.handshake()
print(m.encode_protocol())
print(n.encode_protocol())
print(u.encode_protocol())
k = u.decode_protocol(m.encode_protocol())
print(u.encode_protocol())



dd = hsp.bytedata(raw_data=b'0x1d2a3a4f55')
print(dd.encode_protocol())
uu = hsp.bytedata()
uu.decode_protocol(dd.encode_protocol())
print(uu.encode_protocol())








print('test finished')