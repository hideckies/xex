CC86 := i686-w64-mingw32-g++
CC64 := x86_64-w64-mingw32-g++
CFLAGS := -Wall -O2 -g
OUTDIR := build

SRC_EXE := main_exe.cpp
SRC_DLL := main_dll.cpp

all: init x86_exe x86_dll x64_exe x64_dll

init:
	mkdir -p $(OUTDIR)

x86_exe:
	$(CC86) -m32 $(CFLAGS) -o $(OUTDIR)/hello32.exe $(SRC_EXE)

x86_dll:
	$(CC86) -m32 $(CFLAGS) -shared -o $(OUTDIR)/hello32.dll $(SRC_DLL)

x64_exe:
	$(CC64) $(CFLAGS) -o $(OUTDIR)/hello64.exe $(SRC_EXE)

x64_dll:
	$(CC64) $(CFLAGS) -shared -o $(OUTDIR)/hello64.dll $(SRC_DLL)

clean:
	rm -rf build/*
