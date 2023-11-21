# A sample go application that loads Silkworm API library

## Prerequisites
- C compiler toolchain (required to compile cgo code)

## Build & Run
1. build the silkworm_capi library
2. go to the sample-go-client directory and build the go application specifying the path of the silkworm library:

```bash
go build
```

3. run the application with the environment variable DYLD_LIBRARY_PATH set to find the silkworm library:

```bash
DYLD_LIBRARY_PATH=../../../build/silkworm/capi ./sample-go-client
```
