LDFLAGS =
NASMFLAGS =

sc: sc.o
	ld sc.o -o sc $(LDFLAGS)

sc.o: sc.s
	nasm -f elf64 sc.s -o sc.o $(NASMFLAGS)

sc.bin.txt: exportbin sc.bin
	./exportbin sc.bin

sc.bin: sc.s
	nasm -f bin sc.s -o sc.bin $(NASMFLAGS)

exportbin: exportbin.c
	$(CC) exportbin.c -o exportbin -O3

all: sc.bin.txt sc

clean:
	rm -f *.o sc sc.bin sc.bin.txt exportbin

