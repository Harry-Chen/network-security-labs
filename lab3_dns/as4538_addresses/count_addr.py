import ipaddress

def readfile(filename):
    with open(filename, 'r') as f:
        return list(map(lambda s: ipaddress.ip_network(s.strip()), f))

count = 0
for ipn in readfile('as4538_prefix4.txt'):
    count += ipn.num_addresses
    print(ipn.num_addresses)
    """
    print(ipn.network_address)
    for ip in ipn.hosts():
        print(ip)
    print(ipn.broadcast_address)
    """
print(count)