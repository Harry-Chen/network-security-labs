import math


def ord_at(msg, idx):
    if len(msg) > idx:
        return ord(msg[idx])
    return 0


# 每四个 ASCII 拼接成一个 int32, A B C D -> 0xDCBA
# append_length: 最后是否附加 ASCII 串长度
def ascii_to_int_array(msg, append_length):
    l = len(msg)
    pwd = []
    for i in range(0, l, 4):
        pwd.append(
            ord_at(msg, i) | ord_at(msg, i + 1) << 8 | ord_at(msg, i + 2) << 16
            | ord_at(msg, i + 3) << 24)
    if append_length:
        pwd.append(l)
    return pwd


def int_array_to_ascii(msg):
    l = len(msg)

    for i in range(0, l):
        msg[i] = chr(msg[i] & 0xff) + chr(msg[i] >> 8 & 0xff) + chr(
            msg[i] >> 16 & 0xff) + chr(msg[i] >> 24 & 0xff)

    return "".join(msg)


DELTA = 0x9e3779b9


def xx_tea(t, k, encrypt: bool):

    def m(p):
        r = z >> 5 ^ y << 2
        r = r + ((y >> 3 ^ z << 4) ^ (s ^ y))
        r = r + (k[(p & 3) ^ e] ^ z)
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
            t[-1] = t[-1] + m(n - 2) & 0xFFFFFFFF
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
            t[0] = t[0] - m(1) & 0xFFFFFFFF
            y = t[0]
            s = s - DELTA
            rounds = rounds - 1

    return t


def x_encode(msg, key, encode=True):
    if msg == "":
        return ""

    k = ascii_to_int_array(key, False)

    # 填充密钥至少到 128 位
    if len(k) < 4:
        k = k + [0] * (4 - len(k))

    if encode:
        m = ascii_to_int_array(msg, True)
        return int_array_to_ascii(xx_tea(m, k, True))
    else:
        m = ascii_to_int_array(msg, False)
        return int_array_to_ascii(xx_tea(m, k, False)[0:-1])



