# 实验五：软件安全-漏洞利用实验

- 这是独立完成的实验。

## 实验目标

分析给定的二进制程序`vul32`，发现其中的漏洞，并加以利用。最终实现获得远程服务器的shell，特别地，还要读取`flag`文件。远程服务器地址为`202.112.51.154`，TCP端口`20001`。

提供了二进制程序运行时的C库。

## 实验过程

整个实验分为如下几个步骤：检测二进制程序开启的保护、分析二进制程序存在的漏洞、绕过保护以及取得shell。

### 二进制程序检测

使用GDB的GEF插件中的`checksec`命令检查二进制程序开启的保护措施得到如下结果：

```
gef➤  checksec
[+] checksec for '/home/twd2/nslab/lab5/vul32'
Canary                        : Yes
NX                            : Yes
PIE                           : No
Fortify                       : No
RelRO                         : Partial
```

该结果说明：

* 该程序开启了栈的Canary保护，对栈上缓冲区进行连续的溢出会导致检查不通过。
* 该程序的数据段（栈）不可执行。
* 该程序没有开启位置无关代码，因此即使开启了ASLR，代码段的位置也是确定的。
* 该程序不会自动将`strcpy`等危险函数替换为带检查的函数。
* 该程序的重定位信息部分只读。

此外，假设靶机开启了ASLR。

### 漏洞发现

使用IDA Pro 7.0打开待分析程序，利用其反编译功能得到类C语言的伪代码如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  setbuf(stderr, 0);
  write(1, wel, 30u);
  dovuln();
  return 0;
}
```

```c
void dovuln(void)
{
  int j; // eax
  char chr; // [esp+4h] [ebp-44h]
  char buff[51]; // [esp+5h] [ebp-43h]
  int i; // [esp+38h] [ebp-10h]
  unsigned int canary; // [esp+3Ch] [ebp-Ch]

  canary = __readgsdword(0x14u);
  memset(buff, 0, 0x30u);
  i = 0;
  while ( 1 )
  {
    if ( read(0, &chr, 1u) != 1 )
      exit(0);
    if ( chr == '\n' )
      break;
    j = i++;
    buff[j] = chr;
  }
  puts(buff);
}
```

由代码可知，程序开始执行时输出了30个字符，然后调用`dovuln`函数。由名字可以看出，`dovuln`函数存在缺陷。事实上，`dovuln`函数中的大小为51的`buff`在`buff[j] = chr`语句处存在缓冲区溢出的缺陷。利用此缺陷，可以修改函数的返回地址，从而改变其执行的代码。

### Canary绕过

由于该程序开启了栈的Canary保护，对`buff`进行连续的溢出会导致检查不通过。然而，进一步观察发现，访问`buff`的下标`i`同样存储在栈上，且能够被溢出篡改。由于溢出的首个字节（`buff[51]`）就是下标`i`的最低的字节，若将此字节修改为栈上的函数返回地址相对`buff`的下标，则下一次以及之后的循环迭代对`buff[j]`进行写操作时，实际上是对栈上的返回地址进行写操作。栈上的函数返回地址对应的偏移为`[ebp+4h]`，因此其对应的下标为$\mathtt{0x4} - (-\mathtt{0x43}) = \mathtt{0x47} $。因此，将溢出的首个字节设置为0x47，就可以实现修改返回地址而不破坏canary。

### 泄露C库地址

由于开启了ASLR，C库加载地址是不确定的，为了执行`system`函数来取得shell，需要知道`system`函数在当前进程中的地址。然而，由于该程序没有使用过`system`函数，所以`system`函数的地址不是立即可得的，即在二进制文件中无法找到。

另一方面，该程序在溢出前使用过`read`函数，由动态链接的原理，`.got.plt`段相应条目（该条目的地址是`0x0804A010`）存储了C库中`read`函数在当前进程中的地址。考虑到程序使用过`puts`函数，其`.plt stub`的地址是已知的（`0x08048470`），可以直接调用，就可以利用它将C库中`read`函数在当前进程中的地址泄露出来（输出）。具体而言，需要通过缓冲区溢出合理地对栈进行布局，将`dovuln`函数的返回地址设为`puts`函数的入口，`puts`函数的参数设为`.got.plt`段`read`函数对应条目的地址，`puts`函数的返回地址则设为`main`函数的入口（`0x0804865C`），以便再次进行缓冲区溢出来执行`system`函数。

事实上，通过`.got.plt`段中其他条目，如`setbuf`、`write`或`memset`函数对应的条目，也可以得到类似的结果。

### 计算`system`函数和`/bin/sh`字符串地址

在获得C库中`read`函数在当前进程中的地址后，考虑到动态加载并不会改变C库中代码和数据两两之间的相对位置（偏移），只需要再获得C库中`system`函数与`read`函数之间的偏移以及C库中`/bin/sh`字符串常量与`read`函数之间的偏移，即可用泄露出来的`read`函数在当前进程中的地址计算出当前进程中`system`函数和`/bin/sh`字符串的地址。

本实验提供了服务器上的C库，因此上述偏移容易获得：

* `read`函数的地址是`0x000D4350`
* `system`函数的地址是`0x0003A940`
* `system`函数与`read`函数之间的偏移是`0x0003A940 - 0x000D4350`
* `/bin/sh`字符串常量的地址是`0x0015902B`
* `/bin/sh`字符串常量与`read`函数之间的偏移是`0x0015902B - 0x000D4350`

注意到泄露出来的`read`函数在当前进程中的地址为`0xf7???350`，其低12位（即页内偏移）与上述`read`函数的地址是相符的，说明提供的C库正确、泄露正确。

### 执行`system`函数

这一次，将`dovuln`的返回地址设为`system`函数的入口，`system`函数的参数设为`/bin/sh`字符串的地址。因为无需返回，`system`函数的返回地址可随意选择。待`system`函数被成功执行，立即取得shell。

