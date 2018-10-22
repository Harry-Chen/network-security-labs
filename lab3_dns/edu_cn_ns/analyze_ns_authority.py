def read_zonefile(filename):
    with open(filename, 'r') as f:
        for line in f:
            name, ttl, _, type, value = line.split(None, 4)
            value = value.rstrip()
            yield name, ttl, type, value

authority_servers = {}
glue_records = {}

for name, ttl, type, value in read_zonefile('edu_domain_ns.txt'):
    if type == 'A':
        if name not in glue_records:
            glue_records[name] = value

for name, ttl, type, value in read_zonefile('edu_domain_ns.txt'):
    if type == 'NS':
        name = name[:-1]
        if name not in authority_servers:
            authority_servers[name] = set()
        if value in glue_records:
            ns_ip = glue_records[value]
            record = '{},{}'.format(value[:-1], ns_ip)
            authority_servers[name].add(record)

for name, servers in sorted(authority_servers.items()):
    print('{}:{}'.format(name, ';'.join(sorted(servers))))

