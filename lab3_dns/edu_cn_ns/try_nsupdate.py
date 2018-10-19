#/usr/bin/env python3

import subprocess
import multiprocessing as mp
from threading import Timer

def try_axfr(param):
    domain, name, ip = param
    commands = """server {}
update add nsupdate.{} 600 IN TXT "You have enabled anonymous nsupdate, which is extremely dangerous!"
send""".format(ip, domain)
    p = subprocess.Popen(['nsupdate', '-v', '-d'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE)
    timer = Timer(1.0, p.kill)
    try:
        timer.start()
        out, err = p.communicate(input=commands.encode())
        result = out.decode()
    except:
        result = "timed out"
    finally:
        timer.cancel()

    exclude = ['error', 'REFUSED', 'could not', 'unsuccessful', 'NOTAUTH', 'NOTIMP', 'failed', 'timed out']
    filter_func = lambda s: not any(x in s for x in exclude)

    if "Reply from update query" in result and filter_func(result):
        print('NSUPDATE may success for {}@{}, result:'.format(domain, name))
        with open('nsupdate_result/{}@{}.result'.format(domain, name), 'w') as f:
            f.write(result)
        print(result)
    else:
        print('NSUPDATE failed for {}@{}'.format(domain, name))

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
            for server in ns.split(';'):
                name, ip = server.split(',')
                try_list.append((domain, name, ip))

    pool = mp.Pool(processes=20)
    res = pool.map(try_axfr, try_list)

