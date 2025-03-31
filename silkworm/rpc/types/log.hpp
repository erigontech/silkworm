// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <iostream>
#include <vector>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

namespace silkworm::rpc {

struct Log {
    /* raw fields */
    evmc::address address;
    std::vector<evmc::bytes32> topics;
    silkworm::Bytes data;

    /* derived fields */
    BlockNum block_num{0};
    evmc::bytes32 tx_hash;
    uint32_t tx_index{0};
    evmc::bytes32 block_hash;
    uint32_t index{0};
    bool removed{false};
    std::optional<uint64_t> timestamp{std::nullopt};
};

using Logs = std::vector<Log>;

std::ostream& operator<<(std::ostream& out, const Log& log);

}  // namespace silkworm::rpc
