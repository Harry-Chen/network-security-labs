import os
import time
import random
import collections

fake_ips = collections.defaultdict(int)
ttls = collections.defaultdict(int)
polluted_names = set()

def load_names(f):
  with open(f, 'r') as f:
    return list(filter(bool, map(lambda s: s.strip(), f)))

def handle_polluted(name, answer):
  print(name, 'is polluted!')
  polluted_names.add(name)
  fake_ips[answer[DNS].an.rdata] += 1
  ttls[answer.ttl] += 1

def test1(name):
  p = IP(dst='1.2.3.4')/UDP(sport=random.randint(2048, 65530), dport=53)/DNS(id=random.randint(1, 65535), rd=1, qd=DNSQR(qname=name))
  answers = sr(p, multi=False, timeout=0.1)
  if len(answers[0]) > 0:
    for answer in answers[0]:
      handle_polluted(name, answer[1])

def test2(name):
  p = IP(dst='8.8.8.8')/UDP(sport=random.randint(2048, 65530), dport=53)/DNS(id=random.randint(1, 65535), rd=1, qd=DNSQR(qname=name))
  answers = sr(p, multi=True, timeout=0.5)
  if len(answers[0]) >= 2:
    handle_polluted(name, answers[0][0][1])

def test_list(cat):
  # polluted test case
  # test1('youtube.com')
  # test2('youtube.com')
  # not polluted test case
  # test1('twd2.net')
  # test2('twd2.net')
  # not found case
  # test1('rbvebrefgbhtgrfgbhtgrefghtrefgbrefvgbrefvbgrefwdvrgfrbegrhyjhtrntjythrgf.net')
  # test2('rbvebrefgbhtgrfgbhtgrefghtrefgbrefvgbrefvbgrefwdvrgfrbegrhyjhtrntjythrgf.net')

  global fake_ips, ttls, polluted_names
  fake_ips = collections.defaultdict(int)
  ttls = collections.defaultdict(int)
  polluted_names = set()

  names = load_names('data/alexa/{}.txt'.format(cat))
  for i in range(100):
    for name in names:
      test1(name)
      test2(name)
  with open('data/{}_pollute_report.ip.csv'.format(cat), 'w') as f:
    for ip, count in fake_ips.items():
      f.write('{},{}\n'.format(ip, count))
  with open('data/{}_pollute_report.ttl.csv'.format(cat), 'w') as f:
    for ttl, count in ttls.items():
      f.write('{},{}\n'.format(ttl, count))
  with open('data/{}_pollute_report.txt'.format(cat), 'w') as f:
      f.write('\n'.join(polluted_names) + '\n')

def main():
  test_list('global')
  test_list('computer')

main()
exit()
