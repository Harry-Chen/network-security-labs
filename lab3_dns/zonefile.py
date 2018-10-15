def read_zonefile(filename):
    with open(filename, 'r') as f:
        for line in f:
            name, ttl, _, type, value = line.split(None, 4)
            value = value.rstrip()
            yield name, ttl, type, value

name_servers = {}
for name, ttl, type, value in read_zonefile('data/edu_domain_ns.txt'):
    if type != 'NS':
        continue
    if name not in name_servers:
        name_servers[name] = {value}
    else:
        name_servers[name].add(value)

total = 0
count = 0
for name, servers in name_servers.items():
    total += 1
    if len(servers) == 1:
        print(name, 'has only ONE name server:', list(servers)[0])
        count += 1

print(count, 'of', total, 'domain names have only ONE name server!')