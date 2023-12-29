# ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
# Avoid changes in the code below this point to avoid re-building everything 

FROM cimg/python:3.12 as base

# 1 Install dependencies
RUN sudo apt-get update
RUN sudo apt install -y python3-pip
RUN sudo pip install conan==1.60.2 chardet
RUN sudo apt-get update

# 2 Get repo and submodules
WORKDIR /app
RUN git clone https://github.com/erigontech/silkworm.git project
WORKDIR /app/project
RUN git config submodule.ethereum-tests.update none
RUN git submodule sync
RUN git submodule update --init --recursive

# 3 Install compiler
RUN cmake/setup/compiler_install.sh clang 15
# Alternative way to install clang > 15
# WORKDIR /app
# ARG LLVM_VERSION=16
# RUN sudo wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | sudo tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc
# RUN wget https://apt.llvm.org/llvm.sh
# RUN chmod +x llvm.sh
# RUN sudo ./llvm.sh ${LLVM_VERSION} all
# RUN sudo ln -sfv /usr/bin/clang-${LLVM_VERSION} /usr/bin/clang
# RUN sudo ln -sfv /usr/bin/clang++-${LLVM_VERSION} /usr/bin/clang++
# RUN sudo update-alternatives --install /usr/bin/cc cc /usr/bin/clang-${LLVM_VERSION} 100
# RUN sudo update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++-${LLVM_VERSION} 100

# 4 Build all targets
WORKDIR /app/build
RUN sudo cmake ../project -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_TOOLCHAIN_FILE=../project/cmake/toolchain/clang_libcxx.cmake -DCONAN_PROFILE=linux_clang_13_release -DSILKWORM_FUZZER=ON
WORKDIR /app/project
RUN sudo cmake --build /app/build -j4 

# Avoid changes in the code after this point to avoid re-building everything
# ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑


# Invalidate cache to force rebuild
ARG CACHEBUST
RUN echo $CACHEBUST

# Option 1: Build from branch
RUN echo "Pulling branch" $BRANCH
ARG BRANCH=main
WORKDIR /app/project
RUN git checkout ${BRANCH}
RUN git pull origin ${BRANCH}

# Option 2: Build from local files
# COPY ./silkworm/ /app/project/silkworm/
# COPY ./cmd/ /app/project/cmd/

# Rebuild all targets
RUN echo "Rebuilding"
WORKDIR /app/build
RUN sudo cmake ../project -DCMAKE_BUILD_TYPE=RelWithDebInfo  -DCONAN_PROFILE=linux_clang_13_release -DSILKWORM_FUZZER=ON
WORKDIR /app/project
RUN sudo cmake --build /app/build -j4 --target rpcdaemon_fuzzer_test


# Example of how to run a fuzzer:
# # Copy corpus files
# WORKDIR /app/build
# RUN mkdir -p ~/corpus
# RUN mkdir -p ~/crashes
# RUN mkdir -p ~/artifacts
# RUN for file in ../project/third_party/execution-apis/tests/*/*.io; do cp --backup=numbered "$file" ~/artifacts; done
# RUN for file in ~/artifacts/*; do sed -i '2,$d' "$file"; done
# RUN for file in ~/artifacts/*; do sed -i 's/^>> //' "$file"; done
# # Rebuild fuzzer
# WORKDIR /app/build
# RUN sudo cmake ../project -DCMAKE_BUILD_TYPE=Debug -DCONAN_PROFILE=linux_clang_13_debug -DSILKWORM_FUZZING=ON
# WORKDIR /app/project
# RUN sudo cmake --build /app/build -j4 --target rpcdaemon_fuzzer_test
# # Run fuzzer
# RUN ./cmd/test/rpcdaemon_fuzzer_test -max_total_time=1000 ~/corpus ~/crashes ~/artifacts
