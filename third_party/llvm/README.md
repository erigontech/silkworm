This contains the LLVM libFuzzer fuzzing engine. This has been compiled for linux-x86_64 architecture. This has been linked against the libc++ and libc++abi libraries. 

To re-compile, run the following commands:
```bash
    git clone --branch llvmorg-15.0.7 --single-branch https://github.com/llvm/llvm-project.git
    cd llvm-project
    cmake -S llvm -B build -DLLVM_ENABLE_PROJECTS="clang" -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi;compiler-rt" -DCOMPILER_RT_BUILD_LIBFUZZER=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_TOOLCHAIN_FILE=../silkworm/cmake/toolchain/clang_libcxx.cmake
    cmake --build build
```

The problem with the standard build delivered by the `compiler_install.sh` is that the libFuzzer is linked against the libstdc++ library. This is not compatible with the libc++ library used by the Silkworm project. Therefore, we need to re-compile the libFuzzer library. To prevent the lengthy recompliation of the whole LLVM project, we deliver the pre-compiled libFuzzer library in this repository.

The similar issue has been in https://github.com/google/oss-fuzz/issues/2328.

Update llvm.sh using:

    curl -O https://apt.llvm.org/llvm.sh
