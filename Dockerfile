# ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
# The code should be cached and re-used for each build

FROM cimg/python:3.12.0 as base

ARG BRANCH=ci/rpcdaemon-fuzzer-ci
# 1 Install dependencies
RUN sudo apt-get update
RUN sudo apt install -y python3-pip
RUN sudo pip install conan==1.60.2 chardet
RUN sudo apt-get update

# 2 Get repo and submodules
WORKDIR /app
RUN git clone -b ${BRANCH} https://github.com/erigontech/silkworm.git project

WORKDIR /app/project
RUN git config submodule.ethereum-tests.update none
RUN git submodule sync
RUN git submodule update --init --recursive

# 3 Install compiler
# RUN cmake/setup/compiler_install.sh clang 15

# Alternative way to install clang > 15
WORKDIR /app
ARG LLVM_VERSION=16
RUN sudo wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | sudo tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc
RUN wget https://apt.llvm.org/llvm.sh
RUN chmod +x llvm.sh
RUN sudo ./llvm.sh ${LLVM_VERSION} all
RUN sudo ln -sfv /usr/bin/clang-${LLVM_VERSION} /usr/bin/clang
RUN sudo ln -sfv /usr/bin/clang++-${LLVM_VERSION} /usr/bin/clang++
RUN sudo update-alternatives --install /usr/bin/cc cc /usr/bin/clang-${LLVM_VERSION} 100
RUN sudo update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++-${LLVM_VERSION} 100

# 4 Build all targets
WORKDIR /app/build
RUN cmake ../project -DCMAKE_BUILD_TYPE=Debug -DCONAN_PROFILE=linux_clang_13_debug -DSILKWORM_FUZZER=ON

WORKDIR /app/project
RUN cmake --build /app/build -j4 

# 5 Copy corpus files and run fuzzer
WORKDIR /app/build
RUN mkdir -p ~/corpus
RUN mkdir -p ~/crashes
RUN mkdir -p ~/artifacts
RUN for file in ../project/third_party/execution-apis/tests/*/*.io; do cp --backup=numbered "$file" ~/artifacts; done
RUN for file in ~/artifacts/*; do sed -i '2,$d' "$file"; done
RUN for file in ~/artifacts/*; do sed -i 's/^>> //' "$file"; done
# RUN ./cmd/test/rpcdaemon_fuzzer_test -max_total_time=10 ~/corpus ~/crashes ~/artifacts

# Up to this point
# ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑


# 6 For local builds, copy latest files and build again
# always clean cache at this point
ARG CACHEBUST
RUN echo $CACHEBUST

# copy latest files
# COPY ./silkworm/ /app/project/silkworm/
COPY ./cmd/ /app/project/cmd/

WORKDIR /app/build
RUN cmake ../project -DCMAKE_BUILD_TYPE=Debug -DCONAN_PROFILE=linux_clang_13_debug -DSILKWORM_FUZZER=ON -DSILKWORM_USE_MIMALLOC=OFF

WORKDIR /app/project
# RUN sudo cmake --build /app/build -j4 --target rpcdaemon_fuzzer_diagnostics
RUN cmake --build /app/build -j4 --target rpcdaemon_fuzzer_test
