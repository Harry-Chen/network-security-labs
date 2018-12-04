# 小作业：Linux 系统口令破解

- 2016010981 陈晟祺：借用实验室高端显卡服务器，并运行命令进行破解
- 2015011278 谭闻德：查阅破解方法以及 hashcat 使用方式

shadow 文件记录：

```
test:$6$dRf2Gldj$W4DfAK9vGyz9XCCJrsPOtR7tgf3q6lDH92kE2WKHNXZHfmu7dKFgo5M72jrL2hXJjxcdg596WsWPYYgGrmPZp1:17107:0:99999:7:::
```

已知：密码为 5 位 ASCII 字符。

查阅 Linux shadow 文件记录格式，知该口令为加盐的 SHA512 散列值。

破解命令：

```bash
echo '$6$dRf2Gldj$W4DfAK9vGyz9XCCJrsPOtR7tgf3q6lDH92kE2WKHNXZHfmu7dKFgo5M72jrL2hXJjxcdg596WsWPYYgGrmPZp1' > test.shadow
hashcat -O -m 1800 -a 3 test.shadow "?a?a?a?a?a"
```

借用实验室高端显卡服务器破解，并得到结果如下：

![hashcat](hashcat.jpg)

![hashcat_result](hashcat_result.png)

可知密码为“tls13”。

值得一提的是，谭闻德同学曾尝试使用自己可怜的笔记本电脑进行破解，速度仅有 165H/s，是上述服务器的千分之一，hashcat 报告预估时间需要一年零二百天。

# 实验四：清华校园网身份认证及单点登录安全分析

- 2016010981 陈晟祺：超级大腿
- 2015011278 谭闻德：大腿

## 概述

本实验分析了清华大学校园网身份认证站点（包括校外网络访问认证 net、准入认证 auth4、auth6 以及 auth）以及其他众多校内信息系统的认证方式，讨论了这些认证方式的安全性。

## 实验方法

本实验对于每个校园网身份认证站点（包括校外网络访问认证 net、准入认证 auth4、auth6 以及 auth）以及其他众多校内信息系统站点，分析其**默认**登录方式，检测其是否使用清华大学用户电子身份统一认证凭据（以下简称“使用统一凭据”），以及检测其是否跳转到统一认证系统（id.tsinghua.edu.cn）进行认证（以下简称“跳转”）。

特别地，使用统一认证且没有跳转到统一认证系统进行认证，则说明该站点完全在后台与统一认证系统交互。

本实验将上文提到的登录方式的安全性从高到低按如下顺序排列，并认为同一大类安全性相同：

* id. 跳转到 HTTPS 的统一认证系统（https://id.tsinghua.edu.cn）进行认证
   * before. POST 认证凭据前进行跳转，即用户在统一认证系统提供的表单内填写凭据
   * after. POST 认证凭据到统一认证系统
   * self. 该站点是统一认证系统本身
* https. HTTPS 类
   * post. POST 类
      * plain. 明文 POST 密码
      * hash. 明文 POST 密码的 MD5 或 SHA1 等散列值或消息认证码
      * known_key. POST 密码对称加密后的密文，但对称加密密钥明文传输
* http. HTTP 类
   * post. POST 类
      * plain. 明文 POST 密码
      * hash. 明文 POST 密码的 MD5 或 SHA1 等散列值或消息认证码
      * known_key. POST 密码对称加密后的密文，但对称加密密钥明文传输

注：由于站点接收到用户凭据后可能使用不安全的内部通信将该凭据转发至核心认证服务器，因此本节将 id 的安全性认定为比 https 高。

## 实验结果

| 名称             | 子域名（.tsinghua.edu.cn）| 认证方式 | 是否使用统一凭据 | 备注                       |
| ---------------- | -------------------------- | ---- | ---------------- | -------------------------- |
| 统一认证系统 | id | id.self | 是 |  |
| 校外网络访问认证 | net                        | http.post.hash | 是 |  |
| 准入认证         | auth, auth6         | https.post.known_key | 是      |这两个站点使用同样认证方式|
| 准入认证（IPv4） | auth4 | http.post.known_key | 是 |  |
| 信息门户 | info | https.post.plain | 是 |HTTP嵌入HTTPS表单|
| 教学门户 | academic | https.post.plain | 是 |HTTP嵌入HTTPS表单|
| 网络学堂 | learn | https.post.plain | 是 |HTTP嵌入HTTPS表单|
| 网络学堂（2015） | learn.cic | id.after | 是 |HTTP嵌入HTTPS表单|
| 网络学堂（2018） | learn2018 | id.after | 是 |HTTP嵌入HTTPS表单|
| 云盘 | cloud | id.before | 是 |  |
| Git | git | id.before | 是 |  |

## 结束语

提高我校信息系统的安全水平，任重而道远。

## 附录1 准入认证系统加密算法逆向

上文将准入系统的认证方式认定为“https.post.known_key”或“http.post.known_key”，本节附录进行了进一步的解释。

通过深入分析准入系统前端的 JavaScript 代码，本节发现整个认证过程的本意是一次“挑战—应答”（challenge-response），遗憾的是其在实现方面出了问题。

具体而言，在前端容易观测到准入系统的认证过程如下（去除了无关信息）：

1. 前端向后台服务器请求一个一次性的令牌“token”。
2. 前端将用户提供的明文凭据与一些辅助信息格式化为 `JSON`，使用上一步获得的 token 作为密钥进行加密或散列运算后，编码为 ASCII 字符串，发送到后台服务器。记最终 ASCII 字符串为“info”，加密或散列算法为 E，编码算法为 B。
3. 后台服务器使用 token 和 info 计算认证通过与否，然后反馈给前端。
4. 前端进行进一步处理。

基于 2 和 3，本节猜测算法 E 为可逆的加密算法，否则后台服务器将要明文保存密码。

简单浏览准入系统前端的 JavaScript 代码后，本节发现编码算法 B 采用的函数是 `hashes.min.auth.js` 中的 `Base64.encode()` ，即 Base64 编码。但是将 `hashes.min.auth.js` 与在 GitHub 开源的正版 `hashes.min.auth.js` 比对后，本节发现准入系统将 Base64 编码的字母表由 `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=` 改变为 `LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA=`，试图混淆逆向者。

加密算法 E 使用的函数为 `portal.main.min.js` 中的 `xEncode()`。本节发现，在该文件中，某些常数被拆解为了两个常数的按位或，如 `0x86014019 | 0x183639A0` 或 `0x8CE0D9BF | 0x731F2640`，试图混淆逆向者。其中的大部分，包括`0x8CE0D9BF | 0x731F2640`，在进行常数折叠后结果均为 `0xFFFFFFFF`。用此数做按位与运算，可以将算术运算限制在模 $2^{32}$ 的完全剩余系中，从而正确实现加密算法。剩下一个 `0x86014019 | 0x183639A0` 的结果为 `0x9e3779b9`，这是 TEA（微型加密算法）的一个特征。注意到 TEA 有 XTEA 以及 [XXTEA](https://en.wikipedia.org/wiki/XXTEA) 等变种，经过比对，本节确认算法 E 即为 XXTEA 的加密部分。特别地，加密算法将输入的字节序列视为小端序的 32 位无符号整数序列。若需要，输入的字节序列尾部用零填充。

容易写出算法 B 和算法 E 的逆过程（分别为 `auth_base64.py` 和 `xxtea.py`），从而写出使用 token 和 info 计算明文凭据的算法 `auth_reverse.py `。效果如图所示：

![auth_reverse_test](auth_reverse_test.png)

以下是著名安全专家陈晟祺对此的评价：

> “……可以猜想到，写下这些代码的程序员或许以为自己机智过人，更换了编码算法，混淆了加密算法中的常数，就能掩人耳目，不会被轻易破解。这当然是极度可笑的……事实上这与直接发送明文密码没有区别。但如果在全部 HTTPS 的环境下，也无可厚非。最后令我们更为震惊的是，IPv4 的准入认证页面会主动将 HTTPS 访问的用户跳转到 HTTP （见下图）！这就为不怀好意者提供了一个直接获得用户密码的机会（原本的 net 只能获取 MD5）。我们已经上报学校，希望这一严重问题能尽快得到修复……事实上，正确实现的“挑战—应答”模式确实能有效避免重放攻击，同时也不会泄露明文密码。但不幸的是，SRUN 系统的开发者似乎并没有做到这一点……”
> ![auth_http](strict_http.jpg)

谭闻德同学对此表示：
> “我同意陈专家的说法。”

## 附录2 net 系统的 XSS 漏洞

net.tsinghua.edu.cn 是大部分设备都会用到的校园网登录认证系统。作为一个 Captive Portal，它实现了在认证后跳到用户未认证时尝试访问网页的功能。即，流程为：

1. 用户访问 `http://example.com`
2. 计费网关发现用户未认证，跳转到 `http://net.tsinghua.edu.cn/?url=example.com`
3. 用户认证成功，跳转到 `http://net.tsinghua.edu.cn/wired/?url=example.com`
4. 用户被跳转回 `https://example.com`

其中这一跳转的动作，在对应页面的 JavaScript 脚本中实现为：

```javascript
dst = $.url().param('url');
if (location) location = dst
```

可见此处对参数没有进行任何检查。因此，可以用简单的手段进行 XSS 攻击，比如传入 `url=javascript:alert('Hi')`，结果如下：

![net_xss](net_xss.png)

而由于 net 的一个严重设计缺陷——将用户的密码明文存储在 cookie 中，攻击者借助这一 XSS，可以非常简单地获取用户的敏感信息。只需要在某一用户可能访问到的页面中嵌入一个 `iframe` 指向此页面，并在链接中嵌入代码发送用户的 cookie 到攻击者控制的服务器即可。由于代码是在 net 页面上直接执行的，此攻击可以方便地绕过任何同源/跨域策略的限制（比如修改 `document.domain`）。

而借助另外的漏洞，此漏洞的危害性将会进一步扩大。我们注意到，2001 版网络学堂、2018 版网络学堂的评论区、提交作业等处均存在多个 XSS 注入点，可以插入任意 HTML 代码执行。结合上述信息泄露漏洞，只需要用户查看评论/作业，其凭据就会立刻被泄露。其中，2018 版网络学堂的最初线上版本（9月初），甚至在课程图片处都可进行 XSS，而所有用户登录后都默认跳转到课程列表，其中就有课程的图片；所以用户甚至不需要进行任何操作，登录就会导致被攻击。所幸，2018 版存在的这些问题在上报后都已经被修复（BTW，除了 XSS，还有多个 SQL 注入和用户美剧、任意文件下载等）。而 2001 版的 XSS 问题已经存在多年，工程师也因为明年此系统将被弃用而疏于修复，是一个严重的安全隐患。