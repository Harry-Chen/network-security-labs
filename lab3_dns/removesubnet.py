import ipaddress

def readfile(filename):
    with open(filename, 'r') as f:
        return list(map(lambda s: ipaddress.ip_network(s.split()[0]), list(f)[1:]))

def remove_subnet(l):
    result = []
    for ipn in sorted(l):
        if not result or not ipn.overlaps(result[-1]): # if ipn is not a subnet of result[-1]...
            result.append(ipn)
    return result

henet = remove_subnet(readfile('data/as4538_prefix4_henet.txt'))
cidrreport = remove_subnet(readfile('data/as4538_prefix4_cidrreport.txt'))

with open('data/as4538_prefix4.txt', 'w') as f:
    for ipn in henet:
        f.write(str(ipn) + '\n')
