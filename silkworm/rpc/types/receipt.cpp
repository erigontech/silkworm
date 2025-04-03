// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "receipt.hpp"

#include <iomanip>

#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/bloom.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc {

std::ostream& operator<<(std::ostream& out, const Receipt& r) {
    out << " block_hash: " << to_hex(r.block_hash);
    out << " block_num: " << r.block_num;
    out << " contract_address: " << r.contract_address;
    out << " cumulative_gas_used: " << r.cumulative_gas_used;
    if (r.from) {
        out << " from: " << *r.from;
    } else {
        out << " from: null";
    }
    out << " gas_used: " << r.gas_used;
    out << " #logs: " << r.logs.size();
    auto bloom_view = full_view(r.bloom);
    out << " bloom: " << silkworm::to_hex(bloom_view);
    out << " success: " << r.success;
    if (r.to) {
        out << " to: " << *r.to;
    } else {
        out << " to: null";
    }
    out << " tx_hash: " << to_hex(r.tx_hash);
    out << " tx_index: " << r.tx_index;
    out << " type: 0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(r.type) << std::dec;
    return out;
}

Bloom bloom_from_logs(const Logs& logs) {
    SILK_TRACE << "bloom_from_logs #logs: " << logs.size();
    Bloom bloom{};
    for (auto const& log : logs) {
        m3_2048(bloom, log.address.bytes);
        for (const auto& topic : log.topics) {
            m3_2048(bloom, topic.bytes);
        }
    }
    SILK_TRACE << "bloom_from_logs bloom: " << silkworm::to_hex(full_view(bloom));
    return bloom;
}

}  // namespace silkworm::rpc
