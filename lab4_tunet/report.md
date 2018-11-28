# 实验四：清华校园网身份认证及单点登录安全分析

- 2016010981 陈晟祺：
- 2015011278 谭闻德：

## 概述

本实验分析了清华大学校园网身份认证站点（包括校外网络访问认证 net、准入认证 auth4、auth6 以及 auth）以及其他众多校内信息系统的登录方式，讨论了这些登录方式的安全性。

## 实验方法

本实验对于每个校园网身份认证站点（包括校外网络访问认证 net、准入认证 auth4、auth6 以及 auth）以及其他众多校内信息系统站点，分析其**默认**登录方式，检测其是否使用清华大学用户电子身份统一认证凭据（以下简称“使用统一凭据”），以及检测其是否跳转到统一认证系统（id.tsinghua.edu.cn）进行认证（以下简称“跳转”）。

特别地，使用统一认证且没有跳转到统一认证系统进行认证，则说明该站点完全在后台与统一认证系统交互。

本实验将上文提到的登录方式的安全性从高到低按如下顺序排列，并认为同一大类安全性相同：

* https. HTTPS类
   * post. POST类
      * plain. 明文POST密码
      * hash. 明文POST密码的MD5或SHA1等散列值或消息认证码
      * known_key. POST密码对称加密后的密文，但对称加密密钥明文传输
* http. HTTP类
   * post. POST类
      * plain. 明文POST密码
      * hash. 明文POST密码的MD5或SHA1等散列值或消息认证码
      * known_key. POST密码对称加密后的密文，但对称加密密钥明文传输

## 实验结果

| 名称             | 子域名（.tsinghua.edu.cn）| 登录方式 | 是否使用统一凭据 | 是否跳转 | 备注                       |
| ---------------- | -------------------------- | ---- | ---------------- | -------- | -------------------------- |
| 校外网络访问认证 | net                        | http.post.hash | 是 | 否 ||
| 准入认证         | auth, auth6         | https.post.known_key | 是      | 否 |这两个站点使用同样认证方式|
| 准入认证（IPv4） | auth4 | http.post.known_key | 是 | 否 ||
| 信息门户 | info | https.post.plain | 是 | 否 |HTTP嵌入HTTPS表单|
| 教学门户 | academic | https.post.plain | 是 | 否 |HTTP嵌入HTTPS表单|
| 网络学堂 | learn | https.post.plain | 是 | 否 |HTTP嵌入HTTPS表单|
| 网络学堂（2015） | learn.cic | https.post.plain | 是 | 是 |HTTP嵌入HTTPS表单|
| 网络学堂（2018） | learn2018 | https.post.plain | 是 | 是 |HTTP嵌入HTTPS表单|
| 云盘 | cloud | https.post.plain | 是 | 是 ||
| Git | git | https.post.plain | 是 | 是 ||


## 结束语

