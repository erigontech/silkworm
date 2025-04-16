# A sample go application that loads Silkworm API library

## Prerequisites
- C compiler toolchain (required to compile cgo code)

## Build & Run
1. build the silkworm_capi library
2. go to the sample-go-client directory and run:

```bash
go run main.go
```

on macOS:
```bash
CGO_LDFLAGS=-mmacosx-version-min=15.0 go run main.go
```
