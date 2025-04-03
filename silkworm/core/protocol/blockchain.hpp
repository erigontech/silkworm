// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <unordered_map>
#include <vector>

#include <evmc/evmc.h>

#include <silkworm/core/execution/evm.hpp>
#include <silkworm/core/protocol/rule_set.hpp>
#include <silkworm/core/state/state.hpp>
#include <silkworm/core/types/receipt.hpp>

namespace silkworm::protocol {

/**
 * Reference implementation of Ethereum blockchain logic.
 * Used for running Ethereum EL tests; the real node will use staged sync instead
 * (https://github.com/erigontech/erigon/blob/main/eth/stagedsync/README.md)
 */
class Blockchain {
  public:
    //! Creates a new instance of Blockchain.
    /**
     * In the beginning the state must have the genesis allocation.
     * Later on the state may only be modified by the created instance of Blockchain.
     */
    explicit Blockchain(State& state, const ChainConfig& config, const Block& genesis_block);

    // Not copyable nor movable
    Blockchain(const Blockchain&) = delete;
    Blockchain& operator=(const Blockchain&) = delete;

    ValidationResult insert_block(Block& block, bool check_state_root);

    evmc_vm* exo_evm{nullptr};

  private:
    ValidationResult execute_block(const Block& block, bool check_state_root);

    void prime_state_with_genesis(const Block& genesis_block);

    void re_execute_canonical_chain(uint64_t ancestor, uint64_t tip);

    void unwind_last_changes(uint64_t ancestor, uint64_t tip);

    std::vector<BlockWithHash> intermediate_chain(
        uint64_t block_num,
        evmc::bytes32 hash,
        uint64_t canonical_ancestor) const;

    uint64_t canonical_ancestor(const BlockHeader& header, const evmc::bytes32& hash) const;

    State& state_;
    const ChainConfig& config_;
    RuleSetPtr rule_set_;
    std::unordered_map<evmc::bytes32, ValidationResult> bad_blocks_;
    std::vector<Receipt> receipts_;
};

}  // namespace silkworm::protocol
