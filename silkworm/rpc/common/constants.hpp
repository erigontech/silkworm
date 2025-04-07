// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
