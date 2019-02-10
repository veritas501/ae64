# AE64

AE64 is a tool which can transform any amd64 architecture shellcode into pure **alphanumeric shellcode** using self-modify code technology, so the page need to be writable.

For usage example, you can see example folder.

For older version which I written for HCTF2018 `christmas` pwn challenge, see ver1 folder.



---



There are already some awesome tools for encoding amd64 alphanumeric shellcode, like [https://github.com/SkyLined/alpha3](https://github.com/SkyLined/alpha3).



AE64's pros and cons:

pros:

- more registers which point to shellcode address can be used.
- the register don't need to point right to shellcode's start address, but can with an offset.

cons:

- shellcode's length after encoded is much longer than alpha3.