/*
   Copyright 2021-2022 The Silkworm Authors

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

#include <silkworm/chain/config.hpp>
#include <silkworm/common/base.hpp>

namespace silkworm {

// EIP-2124 based chain identity scheme (networkId + genesis + forks)
struct ChainIdentity {
    const char* name{nullptr};
    ChainConfig config;
    evmc::bytes32 genesis_hash;

    std::vector<BlockNum> distinct_fork_numbers() const;  // helper method
};

inline constexpr ChainIdentity kMainnetIdentity{
    .name = "mainnet",
    .config = kMainnetConfig,
    .genesis_hash = 0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3_bytes32,
};

inline constexpr ChainIdentity kRopstenIdentity{
    .name = "ropsten",
    .config = kRopstenConfig,
    .genesis_hash = 0x41941023680923e0fe4d74a34bdac8141f2540e3ae90623718e47d66d1ca4a2d_bytes32,
};

inline constexpr ChainIdentity kRinkebyIdentity{
    .name = "rinkeby",
    .config = kRinkebyConfig,
    .genesis_hash = 0x6341fd3daf94b748c72ced5a5b26028f2474f5f00d824504e4fa37a75767e177_bytes32,
};

inline constexpr ChainIdentity kGoerliIdentity{
    .name = "goerli",
    .config = kGoerliConfig,
    .genesis_hash = 0xbf7e331f7f7c1dd2e05159666b3bf8bc7a8a3a9eb1d518969eab529dd9b88c1a_bytes32,
};

inline constexpr ChainIdentity kSepoliaIdentity{
    .name = "sepolia",
    .config = kSepoliaConfig,
    .genesis_hash = 0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9_bytes32,
};

}  // namespace silkworm
