import json

from xencode import x_encode, xx_tea
import auth_base64

if __name__ == '__main__':

    data = '''v4+Rz+BhuxtxaGoih/T0xiedDRdWVkRh1kRnGduq9h/VyK2rFWCO0WdGecEkggVD0OwKXLF/z7Y4A+9tYeZ1k6N17z/j9XQZJoxRC735gwluQom+'''
    key = '''3a02ee7646298d2e6e9d836a33be58db92978e1640343be1accf828f7259cafa'''.encode()
    encoded_str = auth_base64.decode(data)
    decoded_str = x_encode(encoded_str, key, False).decode()
    print(json.loads(decoded_str))

