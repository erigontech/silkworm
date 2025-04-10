// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <silkworm/core/types/receipt.hpp>
#include <silkworm/core/types/transaction.hpp>

#include "common/instance.hpp"

struct SilkwormInstance : public capi_todo::SilkwormInstance {
    std::optional<silkworm::ChainConfig> chain_config;

    // TODO: This has to be changed and encapsulated by a proper block caching state
    // Keeps all the receipts created in the current block
    std::vector<silkworm::Receipt> receipts_in_current_block;
    // Keeps all transactions executed in current block
    std::vector<std::pair<silkworm::TxnId, silkworm::Transaction>> transactions_in_current_block;
};
