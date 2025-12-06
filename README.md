💯% 😷 Safe Rust 🦀

Uses the design patterns featured in [https://github.com/Speykious/cve-rs](https://github.com/Speykious/cve-rs)
to safely get pointers to (x64 ELF) C stdlib functions by safely reading program
instruction memory as a &[u8] and looking for the PLT stubs, then computing the
GOT addresses from the offsets encoded in the JMP/CALL instructions. ~~After
demoing, safely derefs a nulled reference for a 🥵 blazingly 🔥 fast segfault.~~

Works on my machine, but may segfault safely for numerous reasons relating to
differences in the program binary when run, such as might exist between binaries
compiled by different versions of `rustc`. (My rustc is v1.91.1.)

![Demo in my terminal](assets/lol.png)

