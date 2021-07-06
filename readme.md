# AE64

AE64 is a tool which can transform any amd64 architecture shellcode into pure alphanumeric shellcode using self-modify code technology, so the page need to be writable.



## Deps

```bash
python3 -m pip install keystone-engine
python3 -m pip install z3-solver
```



## Usage

For usage example, you can see example folder.

### Quickstart

```python
from ae64 import AE64
from pwn import *
context.arch='amd64'

# get bytes format shellcode
shellcode = asm(shellcraft.sh())

# get alphanumeric shellcode
enc_shellcode = AE64().encode(shellcode)
print(enc_shellcode.decode('latin-1'))
```



### About default

```python
enc_shellcode = AE64().encode(shellcode)
# equal to 
enc_shellcode = AE64().encode(shellcode, 'rax', 0, 'fast')

'''
def encode(self, shellcode: bytes, register: str = 'rax', offset: int = 0, strategy: str = 'fast') -> bytes:
"""
encode given shellcode into alphanumeric shellcode (amd64 only)
@param shellcode: bytes format shellcode
@param register: the register contains shellcode pointer (can with offset) (default=rax)
@param offset: the offset (default=0)
@param strategy: encode strategy, can be "fast" or "small" (default=fast)
@return: encoded shellcode
"""
'''
```



### About encode strategy

I write two encode strategy, fast and small.

Fast strategy is the default strategy, it generate alphanumeric shellcode very fast, but the shellcode is a bit long.

Small strategy generate shellcode with the help of z3-solver, so it will be slower but when encoding big shellcode, it can gernerate much smaller shellcode.



### Benchmark

Functionality:

|  | ae64 |   [alpha3](https://github.com/SkyLined/alpha3)   |
| :--- | :------------------------------------------: | :--: |
| Encode x32 alphanumeric shellcode |  ×   | √ |
| Encode x64 alphanumeric shellcode | √ | √ |
| Original shellcode can contain zero bytes | √ | × |
| Base address register can contain offset | √ | × |



Length:

| Origin length(in bytes) | ae64(fast) | ae64(small) | [alpha3](https://github.com/SkyLined/alpha3) |
| ----------------------- | ---------- | ----------- | -------------------------------------------- |
| 2                       | 76         | 143         | 65                                           |
| 48                      | 237        | 209         | 157                                          |
| 192                     | 749        | 425         | 445                                          |
| 576                     | 2074       | 998         | 1213                                         |



## Old story

For older version which I written for HCTF2018 `christmas` pwn challenge, goto branch `old_archive`.

https://github.com/veritas501/ae64/tree/old_archive

ver1 details: https://github.com/veritas501/hctf2018#pwn---christmas4-solves

