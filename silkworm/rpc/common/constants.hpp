/*
   Copyright 2023 The Silkworm Authors

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

namespace silkworm {

constexpr const char* kAdminApiNamespace{"admin"};
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
constexpr const char* kDefaultJwtFile{"jwt.hex"};

constexpr const char* kDefaultEth1EndPoint{"localhost:8545"};
constexpr const char* kDefaultEngineEndPoint{"localhost:8551"};
constexpr const char* kDefaultPrivateApiAddr{"localhost:9090"};
constexpr const char* kDefaultEth1ApiSpec{"admin,debug,eth,net,parity,erigon,trace,web3,txpool"};
constexpr const char* kDefaultEth2ApiSpec{"engine,eth"};
constexpr const std::chrono::milliseconds kDefaultTimeout{10000};

constexpr const std::size_t kHttpIncomingBufferSize{8192};

constexpr const std::size_t kRequestContentInitialCapacity{1024};
constexpr const std::size_t kRequestHeadersInitialCapacity{8};
constexpr const std::size_t kRequestMethodInitialCapacity{64};
constexpr const std::size_t kRequestUriInitialCapacity{64};

}  // namespace silkworm
