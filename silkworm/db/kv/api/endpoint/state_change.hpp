// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <optional>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/infra/concurrency/cancellation_token.hpp>

#include "common.hpp"

namespace silkworm::db::kv::api {

struct StateChangeOptions {
    bool with_storage{false};
    bool with_transactions{false};
    CancellationToken* cancellation_token{nullptr};
};

enum Action : uint8_t {
    kStorage,
    kUpsert,
    kCode,
    kUpsertCode,
    kRemove,
};

struct StorageChange {
    Hash location;
    Bytes data;
};
using StorageChangeSequence = std::vector<StorageChange>;

struct AccountChange {
    evmc::address address;
    uint64_t incarnation{0};
    Action change_type{kStorage};
    Bytes data;
    Bytes code;
    StorageChangeSequence storage_changes;
};
using AccountChangeSequence = std::vector<AccountChange>;

enum Direction : uint8_t {
    kForward,
    kUnwind,
};

struct StateChange {
    Direction direction{kForward};
    BlockNum block_num{0};
    Hash block_hash;
    AccountChangeSequence account_changes;
    ListOfBytes rlp_txs;  // Enabled using StateChangeOptions::with_transactions=true
};
using StateChangeSequence = std::vector<StateChange>;

struct StateChangeSet {
    uint64_t state_version_id{0};        // Unique id of MDBX write transaction where this changes happened
    uint64_t pending_block_base_fee{0};  // Base fee of the next block to be produced
    uint64_t block_gas_limit{0};         // Gas limit of the latest block (proxy for the gas limit of the next block to be produced)
    BlockNum finalized_block{0};
    uint64_t pending_blob_fee_per_gas{0};  // Base blob fee for the next block to be produced
    StateChangeSequence state_changes;
};

using StateChangeConsumer = std::function<Task<void>(std::optional<StateChangeSet>)>;

inline bool operator==(const StorageChange& lhs, const StorageChange& rhs) {
    if (lhs.location != rhs.location) return false;
    if (lhs.data != rhs.data) return false;
    return true;
}

inline bool operator==(const AccountChange& lhs, const AccountChange& rhs) {
    if (lhs.address != rhs.address) return false;
    if (lhs.incarnation != rhs.incarnation) return false;
    if (lhs.change_type != rhs.change_type) return false;
    if (lhs.data != rhs.data) return false;
    if (lhs.code != rhs.code) return false;
    if (lhs.storage_changes != rhs.storage_changes) return false;
    return true;
}

inline bool operator==(const StateChange& lhs, const StateChange& rhs) {
    if (lhs.direction != rhs.direction) return false;
    if (lhs.block_num != rhs.block_num) return false;
    if (lhs.block_hash != rhs.block_hash) return false;
    if (lhs.account_changes != rhs.account_changes) return false;
    if (lhs.rlp_txs != rhs.rlp_txs) return false;
    return true;
}

inline bool operator==(const StateChangeSet& lhs, const StateChangeSet& rhs) {
    if (lhs.state_version_id != rhs.state_version_id) return false;
    if (lhs.pending_block_base_fee != rhs.pending_block_base_fee) return false;
    if (lhs.block_gas_limit != rhs.block_gas_limit) return false;
    if (lhs.finalized_block != rhs.finalized_block) return false;
    if (lhs.pending_blob_fee_per_gas != rhs.pending_blob_fee_per_gas) return false;
    if (lhs.state_changes != rhs.state_changes) return false;
    return true;
}

}  // namespace silkworm::db::kv::api
