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

print(len(auth_base64.decode('D4Smnypi1IxLtSgjfqzMfozxWtL=')))
print(xxtea.decrypt(auth_base64.decode('D4Smnypi1IxLtSgjfqzMfozxWtL='), b'0000000000000000'[:16], padding=False))
print(len(xxtea.decrypt(auth_base64.decode('D4Smnypi1IxLtSgjfqzMfozxWtL='), b'0000000000000000'[:16], padding=False)))

print(auth_base64.decode('D4Smnypi1IxLtSgjfqzMfozxWtL='))
print(xxtea.encrypt(b'0000000000000000\x10\x00\x00\x00', b'0000000000000000', padding=False))