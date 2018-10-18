def read_zonefile(filename):
    with open(filename, 'r') as f:
        for line in f:
            name, ttl, _, type, value = line.split(None, 4)
            # strip the last '.' of FQDN
            name = name[:-1]
            value = value.rstrip()[:-1]
            yield name, ttl, type, value

name_servers = {}
for name, ttl, type, value in read_zonefile('edu_domain_ns.txt'):
    if type != 'NS':
        continue
    if name not in name_servers:
        name_servers[name] = {value}
    else:
        name_servers[name].add(value)

for name, servers in sorted(name_servers.items()):
    print('{}:{}'.format(name, ','.join(servers)))

