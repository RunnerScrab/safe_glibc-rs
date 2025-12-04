Uses the design pattern featured in [https://github.com/Speykious/cve-rs](https://github.com/Speykious/cve-rs) to safely get a pointer to (x64 ELF) C stdlib memset() by safely scanning its own instruction memory for the PLT stub.
Works on my machine, but may segfault safely and blazingly 🔥 fast 🚀 for numerous reasons relating to the exact memory layout of the program when run
