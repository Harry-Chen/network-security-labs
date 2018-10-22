#/usr/bin/env python3

import subprocess
import multiprocessing as mp
from threading import Timer

def try_update(param):
    domain, name, ip = param
    p = subprocess.Popen(['dig', 'nsupdate.{}'.format(domain), '@{}'.format(ip), 'TXT', '+tries=1', '+time=1'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
    out, err = p.communicate()
    result = out.decode()

    if 'dangerous' in result:
        print('NSUPDATE HAS SUCCEEDED for {}@{}, result:'.format(domain, name))
        with open('nsupdate_check/{}@{}.result'.format(domain, name), 'w') as f:
            f.write(result)
        print(result)
    else:
        print('NSUPDATE check failed for {}@{}'.format(domain, name))

    try:
        p.kill()
    except:
        pass


if __name__ == '__main__':
    try_list = []
    with open('ns_report_authority.txt', 'r') as f:
        lines = f.read().splitlines()
        for line in lines:
            domain, ns = line.split(':')
            if not ns:
                continue
            for server in ns.split(';'):
                name, ip = server.split(',')
                try_list.append((domain, name, ip))

    pool = mp.Pool(processes=20)
    res = pool.map(try_update, try_list)

