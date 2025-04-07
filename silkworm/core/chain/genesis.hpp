// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string_view>

#include <nlohmann/json.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/types/block.hpp>

// See https://arvanaghi.com/blog/explaining-the-genesis-block-in-ethereum/

namespace silkworm {

/*
 * \brief Returns genesis data given a known chain_id.
 * If id is not recognized returns an invalid json string
 */
std::string_view read_genesis_data(ChainId chain_id);

BlockHeader read_genesis_header(const nlohmann::json& genesis, const evmc::bytes32& state_root);

InMemoryState read_genesis_allocation(const nlohmann::json& alloc);

}  // namespace silkworm
