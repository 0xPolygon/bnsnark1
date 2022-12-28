# bnsnark1
Go mcl wrapper

## Prerequisite
```
$ sudo apt install libgmp-dev
```

## Usage
```
$ go get https://github.com/0xPolygon/bnsnark1
$ git submodule add https://github.com/herumi/mcl
```
- Change your makefile (`go test` is just an example, place your own application/program there):
```
...
COMMON_PATH=$(shell pwd)/mcl
COMMON_LIB_PATH=$(COMMON_PATH)/lib
PATH_VAL=$$PATH:$(COMMON_LIB_PATH) LD_LIBRARY_PATH=$(COMMON_LIB_PATH) DYLD_LIBRARY_PATH=$(COMMON_LIB_PATH) CGO_CFLAGS="-I$(COMMON_PATH)/include" CGO_LDFLAGS="-L$(COMMON_LIB_PATH)"
...
test:
	cd mcl && make -j4
	env PATH=$(PATH_VAL) go test -coverprofile coverage.out -timeout=20m `go list ./... | grep -v e2e`
```
- ...otherwise set `PATH`, `LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, `CGO_CFLAGS`, `CGO_LDFLAGS` to point to appropriate mcl directories



