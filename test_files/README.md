# Test Files

The files in this directory are used for testing the xex.

<br />

## Build

First, we need to required package for building 32-bit files.

```sh
sudo apt-get install libc6-dev-i386
```

Then execute `make` under specific folder.

```sh
cd elf/hello
make
```

<br />

## Test

```sh
xex hello64
```