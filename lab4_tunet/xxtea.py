import functools
import struct
from enum import Enum
from typing import List


def bytes2ints(data: bytes, append_length: bool=False) -> List[int]:
    ol = len(data)
    if len(data) % 4 != 0:
        data += b'\x00' * (4 - len(data) % 4)
    ints = list(struct.unpack('<' + 'I' * (len(data) // 4), data))
    if append_length:
        ints.append(ol)
    return ints


def ints2bytes(ints: List[int]) -> bytes:
    return struct.pack('<' + 'I' * len(ints), *ints)


class EncryptionMode(Enum):
    Encrypt = 0
    Decrypt = 1


def __xx_tea(t: List[int], k: List[int], mode: EncryptionMode) -> List[int]:

    DELTA = 0x9e3779b9

    def m():
        return ((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4) ^ s ^ y) + (k[(p & 3) ^ e] ^ z)

    n = len(t)
    rounds = 6 + 52 // n

    if mode is EncryptionMode.Encrypt:
        z = t[-1]
        s = 0
        for _ in range(rounds):
            s += DELTA
            e = (s >> 2) & 3
            for p in range(0, n - 1):
                y = t[p + 1]
                z = t[p] = (t[p] + m()) & 0xffffffff
            p = n - 1
            y = t[0]
            z = t[-1] = (t[-1] + m()) & 0xffffffff

    elif mode is EncryptionMode.Decrypt:
        y = t[0]
        s = rounds * DELTA
        for _ in range(rounds):
            e = (s >> 2) & 3
            for p in range(n - 1, 0, -1):
                z = t[p - 1]
                y = t[p] = (t[p] - m()) & 0xffffffff
            p = 0
            z = t[-1]
            y = t[0] = (t[0] - m()) & 0xffffffff
            s -= DELTA

    return t


def endec(msg: bytes, key: bytes, mode: EncryptionMode) -> bytes:
    if not msg:
        return b''

    k = bytes2ints(key, False)
    k.extend([0] * (4 - len(k)))

    if mode is EncryptionMode.Encrypt:
        m = bytes2ints(msg, True)
        return ints2bytes(__xx_tea(m, k, EncryptionMode.Encrypt))
    elif mode is EncryptionMode.Decrypt:
        m = bytes2ints(msg, False)
        return ints2bytes(__xx_tea(m, k, EncryptionMode.Decrypt)[0:-1]).rstrip(b'\x00')


encrypt = functools.partial(endec, mode=EncryptionMode.Encrypt)
decrypt = functools.partial(endec, mode=EncryptionMode.Decrypt)
