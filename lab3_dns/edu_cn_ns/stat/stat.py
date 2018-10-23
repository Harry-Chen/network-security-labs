#/usr/bin/env python3

def read_set(filename):
    with open(filename, 'r') as f:
        return set(map(lambda s: s.strip(), f))

num_ns = {}

with open('../ns_report_authority.txt', 'r') as f:
    lines = f.read().splitlines()
    for line in lines:
        domain, ns = line.split(':')
        if not ns:
            num_ns[domain] = 0
        else:
            num_ns[domain] = len(ns.split(';'))

count = {1: 0, 2: 0, 3: 0}
for name in sorted(read_set('axfr.txt')):
    print(name, num_ns[name])
    count[num_ns[name]] += 1
print(count)
print()

count = {1: 0, 2: 0, 3: 0}
for name in sorted(read_set('nsupdate.txt')):
    print(name, num_ns[name])
    count[num_ns[name]] += 1
print(count)
print()