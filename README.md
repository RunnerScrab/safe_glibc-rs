💯% 😷 Safe Rust 🦀

Uses the techniques featured in [https://github.com/Speykious/cve-rs](https://github.com/Speykious/cve-rs)
to get pointers to imported system and C runtime lib functions by reading
program instruction memory as a &[u8], and looking for the PLT stubs or call
sites. From these, the GOT/IAT addresses can be computed from the offsets
encoded in the JMP/CALL instructions, then cast into callable Rust function
pointers of any signature using transmute<A,B>().

~~After demoing, safely derefs a nulled reference for a 🥵 blazingly 🔥 fast
segfault.~~

Works on my machine, but may segfault safely for numerous reasons relating to
differences in the program binary when run, such as might exist between
binaries compiled by different versions of `rustc`. (My rustc is v1.91.1.)

![Demo in my terminal](assets/lol.png)

