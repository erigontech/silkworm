// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>
#include <string_view>

namespace silkworm {

inline constexpr std::string_view kAdminApiNamespace{"admin"};
inline constexpr std::string_view kDebugApiNamespace{"debug"};
inline constexpr std::string_view kEngineApiNamespace{"engine"};
inline constexpr std::string_view kEthApiNamespace{"eth"};
inline constexpr std::string_view kNetApiNamespace{"net"};
inline constexpr std::string_view kParityApiNamespace{"parity"};
inline constexpr std::string_view kErigonApiNamespace{"erigon"};
inline constexpr std::string_view kTxPoolApiNamespace{"txpool"};
inline constexpr std::string_view kTraceApiNamespace{"trace"};
inline constexpr std::string_view kWeb3ApiNamespace{"web3"};
inline constexpr std::string_view kOtterscanApiNamespace{"ots"};

inline constexpr std::string_view kAddressPortSeparator{":"};
inline constexpr std::string_view kApiSpecSeparator{","};
inline constexpr std::string_view kDefaultJwtFile{"jwt.hex"};

inline constexpr std::string_view kDefaultEth1EndPoint{"127.0.0.1:8545"};
inline constexpr std::string_view kDefaultEngineEndPoint{"127.0.0.1:8551"};
inline constexpr std::string_view kDefaultPrivateApiAddr{"127.0.0.1:9090"};
inline constexpr std::string_view kDefaultEth1ApiSpec{"admin,debug,eth,net,parity,erigon,trace,web3,txpool"};
inline constexpr std::string_view kDefaultEth2ApiSpec{"engine,eth"};
inline constexpr std::chrono::milliseconds kDefaultTimeout{10000};

}  // namespace silkworm
