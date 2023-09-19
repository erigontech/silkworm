# A sample go application that loads Silkworm API library

## Prerequisites
- c++ toolchain (required to compile cgo code)
- go toolchain

## Build & Run
1. build the silkworm library
2. go to the sample-go-client directory and build the go application specifying the path of the silkworm library:

```bash
CGO_LDFLAGS="-L/home/user/silkworm/build_debug/silkworm/api -lsilkworm_api -lstdc++ -ldl" go build
```

3. run the application with the environment variable DYLD_LIBRARY_PATH set to find the silkworm library:

```bash
export DYLD_LIBRARY_PATH=/home/user/silkworm/build_debug/silkworm/api
./sample-go-client
```

