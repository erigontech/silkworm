// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "chain_config.hpp"

#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc {

std::ostream& operator<<(std::ostream& out, const ChainConfig& chain_config) {
    out << "genesis: " << to_hex(chain_config.genesis_hash.value_or(evmc::bytes32{})) << " "
        << "config: " << chain_config.to_json().dump();
    return out;
}

}  // namespace silkworm::rpc
