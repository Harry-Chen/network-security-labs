import ipaddress

with open('as4538_public_ns.txt', 'r') as f:
    ips = list(map(str, sorted(map(lambda s: ipaddress.ip_address(s.strip()), f))))

print('\n'.join(ips) + '\n')