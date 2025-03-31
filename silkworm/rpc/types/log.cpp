// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "log.hpp"

#include <iomanip>

#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc {

std::ostream& operator<<(std::ostream& out, const Log& log) {
    out << "#topics: " << log.topics.size();
    out << " #data: " << log.data.size();
    out << " block_num: " << static_cast<uint32_t>(log.block_num);
    out << " tx_hash: " << to_hex(log.tx_hash);
    out << " tx_index: " << log.tx_index;
    out << " block_hash: " << to_hex(log.block_hash);
    out << " index: " << log.index;
    out << " removed: " << log.removed;
    out << " address: ";
    for (const auto& b : log.address.bytes) {
        out << std::hex << std::setw(2) << std::setfill('0') << int{b};
    }
    out << std::dec;
    return out;
}

}  // namespace silkworm::rpc
