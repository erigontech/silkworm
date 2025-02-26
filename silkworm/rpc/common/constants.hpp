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

namespace silkworm {

inline constexpr const char* kAdminApiNamespace{"admin"};
inline constexpr const char* kDebugApiNamespace{"debug"};
inline constexpr const char* kEngineApiNamespace{"engine"};
inline constexpr const char* kEthApiNamespace{"eth"};
inline constexpr const char* kNetApiNamespace{"net"};
inline constexpr const char* kParityApiNamespace{"parity"};
inline constexpr const char* kErigonApiNamespace{"erigon"};
inline constexpr const char* kTxPoolApiNamespace{"txpool"};
inline constexpr const char* kTraceApiNamespace{"trace"};
inline constexpr const char* kWeb3ApiNamespace{"web3"};
inline constexpr const char* kOtterscanApiNamespace{"ots"};

inline constexpr const char* kAddressPortSeparator{":"};
inline constexpr const char* kApiSpecSeparator{","};
inline constexpr const char* kDefaultJwtFile{"jwt.hex"};

inline constexpr const char* kDefaultEth1EndPoint{"127.0.0.1:8545"};
inline constexpr const char* kDefaultEngineEndPoint{"127.0.0.1:8551"};
inline constexpr const char* kDefaultPrivateApiAddr{"127.0.0.1:9090"};
inline constexpr const char* kDefaultEth1ApiSpec{"admin,debug,eth,net,parity,erigon,trace,web3,txpool"};
inline constexpr const char* kDefaultEth2ApiSpec{"engine,eth"};
inline constexpr std::chrono::milliseconds kDefaultTimeout{10000};

}  // namespace silkworm
