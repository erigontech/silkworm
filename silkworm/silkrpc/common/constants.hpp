/*
   Copyright 2020 The Silkrpc Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#pragma once

#include <chrono>
#include <cstddef>

namespace silkrpc {

constexpr const char* kDebugApiNamespace{"debug"};
constexpr const char* kEngineApiNamespace{"engine"};
constexpr const char* kEthApiNamespace{"eth"};
constexpr const char* kNetApiNamespace{"net"};
constexpr const char* kParityApiNamespace{"parity"};
constexpr const char* kErigonApiNamespace{"erigon"};
constexpr const char* kTxPoolApiNamespace{"txpool"};
constexpr const char* kTraceApiNamespace{"trace"};
constexpr const char* kWeb3ApiNamespace{"web3"};
constexpr const char* kOtterscanApiNamespace{"ots"};

constexpr const char* kAddressPortSeparator{":"};
constexpr const char* kApiSpecSeparator{","};
constexpr const char* kDefaultJwtFilename{"jwt.hex"};

constexpr const char* kEmptyChainData{""};
constexpr const char* kDefaultHttpPort{"localhost:8545"};
constexpr const char* kDefaultEnginePort{"localhost:8551"};
constexpr const char* kDefaultTarget{"localhost:9090"};
constexpr const char* kDefaultEth1ApiSpec{"debug,eth,net,parity,erigon,trace,web3,txpool"};
constexpr const char* kDefaultEth2ApiSpec{"engine,eth"};
constexpr const char* kDefaultDataDir{""};
constexpr const std::chrono::milliseconds kDefaultTimeout{10000};

constexpr const std::size_t kHttpIncomingBufferSize{8192};

constexpr const std::size_t kRequestContentInitialCapacity{1024};
constexpr const std::size_t kRequestHeadersInitialCapacity{8};
constexpr const std::size_t kRequestMethodInitialCapacity{64};
constexpr const std::size_t kRequestUriInitialCapacity{64};

} // namespace silkrpc

