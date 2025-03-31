// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <intx/intx.hpp>

namespace silkworm::rpc {

struct ChainTraffic {
    intx::uint<256> cumulative_gas_used;
    uint64_t cumulative_transactions_count{0};
};

}  // namespace silkworm::rpc
