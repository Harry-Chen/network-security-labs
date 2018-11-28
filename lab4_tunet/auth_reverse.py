import json

import xxtea
import auth_base64


def test(info: str, key: str):
    print('\nKey: {}\nCipher: {}'.format(key, info))
    cipher = auth_base64.decode(info)
    plain = xxtea.decrypt(cipher, key.encode())
    print('Plain text: {}'.format(json.loads(plain)))
    cipher2 = xxtea.encrypt(plain, key.encode())
    print('encrypt(decrypt(Cipher)) == Cipher: {}'.format(cipher == cipher2))


if __name__ == '__main__':
    test('v4+Rz+BhuxtxaGoih/T0xiedDRdWVkRh1kRnGduq9h/VyK2rFWCO0WdGecEkggVD0OwKXLF/z7Y4A+9tYeZ1k6N17z/j9XQZJoxRC735gwluQom+',
         '3a02ee7646298d2e6e9d836a33be58db92978e1640343be1accf828f7259cafa')
    test('GneLzHuQ6Uewc5HVC7aMqGQcUrjCHpa3b0jUrc5SdpDCxKKVx40tbop+6aFmuDDS+pW4YLhi55KjYtl5TAT4J2bgHRUzmNBKI599oZ1MJmK6BzjBnHmq8L==',
         '81c860ffc138df6b5e1b4ab6378c91fb287e502d1b69ed4cdd7d2c29d47cb6f2')
