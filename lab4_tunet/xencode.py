import math
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


DELTA = 0x9e3779b9


def xx_tea(t, k, encrypt: bool):

    def m(a):
        r = z >> 5 ^ y << 2
        r = r + ((y >> 3 ^ z << 4) ^ (s ^ y))
        r = r + (k[(a & 3) ^ e] ^ z)
        return r

    n = len(t)
    rounds = math.floor(6 + 52 / n)

    if encrypt:
        z = t[-1]
        s = 0
        while rounds > 0:
            s = s + DELTA
            e = (s >> 2) & 3
            for p in range(0, n - 1):
                y = t[p + 1]
                t[p] = t[p] + m(p) & 0xFFFFFFFF
                z = t[p]
            y = t[0]
            t[-1] = t[-1] + m(n - 1) & 0xFFFFFFFF
            z = t[-1]
            rounds = rounds - 1

    else:
        y = t[0]
        s = rounds * DELTA
        while rounds > 0:
            e = (s >> 2) & 3
            for p in reversed(range(1, n)):
                z = t[p - 1]
                t[p] = t[p] - m(p) & 0xFFFFFFFF
                y = t[p]
            z = t[-1]
            t[0] = t[0] - m(0) & 0xFFFFFFFF
            y = t[0]
            s = s - DELTA
            rounds = rounds - 1

    return t


def x_encode(msg, key, encode=True):

    if msg == "":
        return ""

    k = bytes2ints(key, False)

    # 填充密钥至少到 128 位
    if len(k) < 4:
        k = k + [0] * (4 - len(k))

    if encode:
        m = bytes2ints(msg, True)
        return ints2bytes(xx_tea(m, k, True))
    else:
        m = bytes2ints(msg, False)
        return ints2bytes(xx_tea(m, k, False)[0:-1])



