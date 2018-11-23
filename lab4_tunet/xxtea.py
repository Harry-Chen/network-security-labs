import functools
import struct

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


def __xxtea(t, k, encrypt):
    DELTA = 0x9e3779b9

    def m():
        return (z >> 5 ^ y << 2) + ((y >> 3 ^ z << 4) ^ (s ^ y)) + (k[(p & 3) ^ e] ^ z)

    n = len(t)
    rounds = 6 + 52 // n

    if encrypt:
        z = t[-1]
        s = 0
        while rounds > 0:
            s = s + DELTA
            e = (s >> 2) & 3
            for p in range(0, n - 1):
                y = t[p + 1]
                t[p] = t[p] + m() & 0xffffffff
                z = t[p]
            p = n - 1
            y = t[0]
            t[-1] = t[-1] + m() & 0xffffffff
            z = t[-1]
            rounds = rounds - 1
    else:
        y = t[0]
        s = rounds * DELTA
        while rounds > 0:
            e = (s >> 2) & 3
            for p in range(n - 1, 0, -1):
                z = t[p - 1]
                t[p] = t[p] - m() & 0xffffffff
                y = t[p]
            p = 0
            z = t[-1]
            t[0] = t[0] - m() & 0xffffffff
            y = t[0]
            s = s - DELTA
            rounds = rounds - 1

    return t


def endec(msg, key, encrypt=True):
    if not msg:
        return b''

    k = bytes2ints(key, False)
    k.extend([0] * (4 - len(k)))

    if encrypt:
        m = bytes2ints(msg, True)
        return ints2bytes(__xxtea(m, k, True))
    else:
        m = bytes2ints(msg, False)
        return ints2bytes(__xxtea(m, k, False)[0:-1]).rstrip(b'\x00')


encrypt = functools.partial(endec, encrypt=True)
decrypt = functools.partial(endec, encrypt=False)
