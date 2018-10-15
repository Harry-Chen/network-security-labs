with open('data/edu_domain_ns_dig.txt', 'r') as f:
    data = list(filter(lambda s: s.strip() and s[0] != ';', f))

with open('data/edu_domain_ns.txt', 'w') as f:
    for d in data:
        f.write(d)