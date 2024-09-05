CC = gcc
SRC = hello.c
OUTDIR = build

all: x86 x64

x86:
	mkdir -p build
	$(CC) -m32 -g -o $(OUTDIR)/hello32 $(SRC)
	$(CC) -m32 -g -shared -fPIC -o $(OUTDIR)/hello32.so $(SRC)

x64:
	mkdir -p build
	$(CC) -m64 -g -o $(OUTDIR)/hello64 $(SRC)
	$(CC) -m64 -g -shared -fPIC -o $(OUTDIR)/hello64.so $(SRC)

clean:
	rm -rf build/*