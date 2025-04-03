// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "chain_config.hpp"

#include <sstream>

#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc {

std::string chain_config_to_string(const ChainConfig& chain_config) {
    std::stringstream out;
    out << "genesis: " << to_hex(chain_config.genesis_hash.value_or(evmc::bytes32{})) << " "
        << "config: " << chain_config.to_json().dump();
    return out.str();
}

std::ostream& operator<<(std::ostream& out, const ChainConfig& chain_config) {
    out << chain_config_to_string(chain_config);
    return out;
}

}  // namespace silkworm::rpc
