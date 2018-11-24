import base64

ORIG = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
AUTH = 'LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA='

auth2orig = dict(zip(AUTH, ORIG))
orig2auth = dict(zip(ORIG, AUTH))


def encode(data: bytes) -> str:
    return ''.join(map(lambda c: orig2auth[c], base64.b64encode(data).decode()))


def decode(s: str) -> bytes:
    return base64.b64decode(''.join(map(lambda c: auth2orig[c], s)))
