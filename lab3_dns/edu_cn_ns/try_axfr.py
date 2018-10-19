#/usr/bin/env python3

import subprocess
import multiprocessing as mp

def try_axfr(param):
    domain, name, ip = param
    p = subprocess.Popen(['dig', '+time=1', '+tries=1', '@{}'.format(ip), 'AXFR', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    out, err = p.communicate()
    result = out.decode()
    if 'failed' not in result and 'timed out' not in result and 'error' not in result:
        print('AXFR succeeded for {}@{}, result:'.format(domain, name))
        with open('axfr_result/{}@{}.zone'.format(domain, name), 'w') as f:
            f.write(result)
        print(result)
    else:
        print('AXFR failed for {}@{}'.format(domain, name))


if __name__ == '__main__':
    try_list = []
    with open('ns_report_authority.txt', 'r') as f:
        lines = f.read().splitlines()
        for line in lines:
            domain, ns = line.split(':')
            for server in ns.split(';'):
                name, ip = server.split(',')
                try_list.append((domain, name, ip))

    pool = mp.Pool(processes=20)
    res = pool.map(try_axfr, try_list)

