def read_zonefile(filename):
    with open(filename, 'r') as f:
        for line in f:
            name, ttl, _, type, value = line.split(None, 4)
            # strip the last '.' of FQDN
            name = name
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
        try:
            name = name[:-1]
            ns_ip = glue_records[value]
            record = '{},{}'.format(value[:-1], ns_ip)
            if name not in authority_servers:
                authority_servers[name] = {record}
            else:
                authority_servers[name].add((record))
        except:
            pass

for name, servers in sorted(authority_servers.items()):
    print('{}:{}'.format(name, ';'.join(servers)))

