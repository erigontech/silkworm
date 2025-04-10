// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <string>

#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/db/tables.hpp>

namespace silkworm::db {

inline constexpr BlockNum kFullImmutabilityThreshold{90'000};

// TODO(Andrea) Prune mode persistence (as in Erigon) is excessively convoluted
// Need refactoring when/if Erigon db compatibility can be broken

inline constexpr std::string_view kPruneModeHistoryKey{"pruneHistory"};
inline constexpr std::string_view kPruneModeReceiptsKey{"pruneReceipts"};
inline constexpr std::string_view kPruneModeSendersKey{"pruneSenders"};
inline constexpr std::string_view kPruneModeTxIndexKey{"pruneTxIndex"};
inline constexpr std::string_view kPruneModeCallTracesKey{"pruneCallTraces"};

using PruneDistance = std::optional<BlockNum>;   // for 'older' type
using PruneThreshold = std::optional<BlockNum>;  // for 'before' type

class BlockAmount {
  public:
    enum class Type : uint8_t {
        kOlder,  // Prune Data Older than (moving window)
        kBefore  // Prune data before (fixed)
    };

    BlockAmount() = default;

    explicit BlockAmount(Type type, BlockNum value) : value_{value}, enabled_{true}, type_{type} {}

    bool enabled() const { return enabled_; }
    Type type() const { return type_; };
    BlockNum value() const;
    BlockNum value_from_head(BlockNum stage_head) const;

    void to_string(std::string& short_form, std::string& long_form, char prefix) const;

    friend bool operator==(const BlockAmount&, const BlockAmount&) = default;

  private:
    std::optional<BlockNum> value_;
    bool enabled_{false};
    Type type_{Type::kOlder};
};

class PruneMode {
  public:
    PruneMode() = default;

    explicit PruneMode(BlockAmount history, BlockAmount receipts, BlockAmount senders, BlockAmount tx_index,
                       BlockAmount call_traces)
        : history_{history},
          receipts_{receipts},
          senders_{senders},
          tx_index_{tx_index},
          call_traces_{call_traces} {}

    const BlockAmount& history() const { return history_; }
    const BlockAmount& receipts() const { return receipts_; }
    const BlockAmount& senders() const { return senders_; }
    const BlockAmount& tx_index() const { return tx_index_; }
    const BlockAmount& call_traces() const { return call_traces_; }

    std::string to_string() const;

    friend bool operator==(const PruneMode&, const PruneMode&) = default;

  private:
    BlockAmount history_;      // Holds the pruning threshold for history
    BlockAmount receipts_;     // Holds the pruning threshold for receipts
    BlockAmount senders_;      // Holds the pruning threshold for senders
    BlockAmount tx_index_;     // Holds the pruning threshold for tx_index
    BlockAmount call_traces_;  // Holds the pruning threshold for call traces
};

//! \brief Reads pruning mode from db
//! \param [in] txn : a db transaction
//! \return A PruneMode struct instance
PruneMode read_prune_mode(mdbx::txn& txn);

//! \brief Writes prune mode to db
//! \param [in] txn : a db transaction
//! \param [in] value : the PruneMode to be persisted
void write_prune_mode(mdbx::txn& txn, const PruneMode& value);

//! \brief Parses prune mode from a string
//! \param [in] mode : the string representation of PruneMode
PruneMode parse_prune_mode(const std::string& mode, const PruneDistance& older_history,
                           const PruneDistance& older_receipts, const PruneDistance& older_senders,
                           const PruneDistance& older_tx_index, const PruneDistance& older_call_traces,
                           const PruneThreshold& before_history, const PruneThreshold& before_receipts,
                           const PruneThreshold& before_senders, const PruneThreshold& before_tx_index,
                           const PruneThreshold& before_call_traces);

}  // namespace silkworm::db
