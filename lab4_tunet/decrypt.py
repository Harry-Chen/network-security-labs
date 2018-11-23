import struct
import xxtea # python3 -m pip install xxtea
import auth_base64

def bytes2ints(data, append_length=False):
    ol = len(data)
    if len(data) % 4 != 0:
        data += b'\x00' * (4 - len(data) % 4)
    ints = list(struct.unpack('<' + 'I' * (len(data) // 4), data))
    if append_length:
        ints.append(ol)
    return ints

def ints2bytes(ints):
    return struct.pack('<' + 'I' * len(ints), *ints)

print(bytes2ints(b'123456', True))
print(bytes2ints(b'123456', False))
print(ints2bytes([1,2,3,4]))