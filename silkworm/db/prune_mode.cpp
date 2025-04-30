// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "prune_mode.hpp"

#include <stdexcept>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>

namespace silkworm::db {

using datastore::kvdb::from_slice;
using datastore::kvdb::to_slice;

//! \brief Retrieves the proper BlockAmount prune threshold for given key
static BlockAmount read_block_amount_for_key(mdbx::cursor& source, std::string_view key) {
    std::string key_str{key};
    auto data{source.find(mdbx::slice(key_str), /*throw_notfound=*/false)};
    if (data.done) {
        // Grab numeric value
        auto value{endian::load_big_u64(from_slice(data.value).data())};

        // Lookup type of pruning (before/older)
        key_str += "Type";
        BlockAmount::Type value_type{BlockAmount::Type::kOlder};
        auto data2{source.find(mdbx::slice(key_str), /*throw_notfound=*/false)};
        if (data2.done) {
            if (data2.value.as_string() == "older") {
                value_type = BlockAmount::Type::kOlder;
                // For compatibility reasons with Erigon we assume a value == UINT64_MAX means no pruning
                if (value == UINT64_MAX) {
                    return {};
                }
            } else if (data2.value.as_string() == "before") {
                value_type = BlockAmount::Type::kBefore;
            } else {
                // Something bad has been written
                throw std::runtime_error("Invalid prune type stored in database : " + std::string(data2.value.as_string()));
            }
        }
        return BlockAmount(value_type, value);
    }
    return {};
}

//! \brief Writes the BlockAmount keys in db
static void write_block_amount_for_key(mdbx::cursor& target, std::string_view key, const BlockAmount& block_amount) {
    std::string db_key{key};
    std::string db_type{"older"};
    Bytes db_value(sizeof(BlockNum), '\0');

    if (!block_amount.enabled()) {
        endian::store_big_u64(db_value.data(), UINT64_MAX);
        target.upsert(mdbx::slice(db_key), to_slice(db_value));
        db_key += "Type";
        target.upsert(mdbx::slice(db_key), mdbx::slice(db_type));
        return;
    }

    endian::store_big_u64(db_value.data(), block_amount.value());
    target.upsert(mdbx::slice(db_key), to_slice(db_value));
    db_key += "Type";
    db_type = (block_amount.type() == BlockAmount::Type::kOlder ? "older" : "before");
    target.upsert(mdbx::slice(db_key), mdbx::slice(db_type));
}

void BlockAmount::to_string(std::string& short_form, std::string& long_form, char prefix) const {
    if (!enabled()) return;
    if (type() == BlockAmount::Type::kOlder) {
        if (value() == kFullImmutabilityThreshold) {
            short_form += prefix;
        } else {
            long_form += " --prune.";
            long_form += prefix;
            long_form += (".older=" + std::to_string(value()));
        }
    } else {
        long_form += " --prune.";
        long_form += prefix;
        long_form += (".before=" + std::to_string(value()));
    }
}

BlockNum BlockAmount::value() const {
    if (!enabled()) {
        return 0;
    }
    switch (type_) {
        case Type::kOlder:
            return value_.has_value() ? *value_ : kFullImmutabilityThreshold;
        case Type::kBefore:
            return value_.has_value() ? *value_ : 0;
        default:
            // Should not happen but this removes a compilation warning
            throw std::runtime_error("Invalid type");
    }
}

BlockNum BlockAmount::value_from_head(BlockNum stage_head) const {
    if (!stage_head || !enabled_ || !value_) {
        return 0;
    }

    const BlockNum prune_value{value()};
    switch (type_) {
        case Type::kOlder:  // See Erigon prune mode Distance interface
            if (prune_value >= stage_head) return 0;
            return stage_head - prune_value;
        case Type::kBefore:  // See Erigon prune mode Before interface
            if (!prune_value) return 0;
            return prune_value - 1;
        default:
            return 0;  // Should not happen
    }
}

std::string PruneMode::to_string() const {
    std::string short_form{"--prune="};
    std::string long_form{};

    history_.to_string(short_form, long_form, 'h');
    receipts_.to_string(short_form, long_form, 'r');
    senders_.to_string(short_form, long_form, 's');
    tx_index_.to_string(short_form, long_form, 't');
    call_traces_.to_string(short_form, long_form, 'c');

    return short_form + long_form;
}

PruneMode read_prune_mode(mdbx::txn& txn) {
    auto src = datastore::kvdb::open_cursor(txn, table::kDatabaseInfo);

    auto history{read_block_amount_for_key(src, kPruneModeHistoryKey)};
    auto receipts{read_block_amount_for_key(src, kPruneModeReceiptsKey)};
    auto senders{read_block_amount_for_key(src, kPruneModeSendersKey)};
    auto tx_index{read_block_amount_for_key(src, kPruneModeTxIndexKey)};
    auto call_traces{read_block_amount_for_key(src, kPruneModeCallTracesKey)};
    return PruneMode{history, receipts, senders, tx_index, call_traces};
}

void write_prune_mode(mdbx::txn& txn, const PruneMode& value) {
    auto target = datastore::kvdb::open_cursor(txn, table::kDatabaseInfo);
    write_block_amount_for_key(target, kPruneModeHistoryKey, value.history());
    write_block_amount_for_key(target, kPruneModeReceiptsKey, value.receipts());
    write_block_amount_for_key(target, kPruneModeSendersKey, value.senders());
    write_block_amount_for_key(target, kPruneModeTxIndexKey, value.tx_index());
    write_block_amount_for_key(target, kPruneModeCallTracesKey, value.call_traces());
}

PruneMode parse_prune_mode(const std::string& mode, const PruneDistance& older_history,
                           const PruneDistance& older_receipts, const PruneDistance& older_senders,
                           const PruneDistance& older_tx_index, const PruneDistance& older_call_traces,
                           const PruneThreshold& before_history, const PruneThreshold& before_receipts,
                           const PruneThreshold& before_senders, const PruneThreshold& before_tx_index,
                           const PruneThreshold& before_call_traces) {
    std::optional<BlockAmount> history, receipts, senders, tx_index, call_traces;

    if (!mode.empty() && !(iequals(mode, "default") || iequals(mode, "disabled"))) {
        for (const auto& c : mode) {
            switch (c) {
                case 'h':
                    history = BlockAmount(BlockAmount::Type::kOlder, kFullImmutabilityThreshold);
                    break;
                case 'r':
                    receipts = BlockAmount(BlockAmount::Type::kOlder, kFullImmutabilityThreshold);
                    break;
                case 's':
                    senders = BlockAmount(BlockAmount::Type::kOlder, kFullImmutabilityThreshold);
                    break;
                case 't':
                    tx_index = BlockAmount(BlockAmount::Type::kOlder, kFullImmutabilityThreshold);
                    break;
                case 'c':
                    call_traces = BlockAmount(BlockAmount::Type::kOlder, kFullImmutabilityThreshold);
                    break;
                default:
                    throw std::invalid_argument("Invalid mode");
            }
        }
    }

    // Apply discrete values for 'older' if provided
    if (older_history) history = BlockAmount(BlockAmount::Type::kOlder, *older_history);
    if (older_receipts) receipts = BlockAmount(BlockAmount::Type::kOlder, *older_receipts);
    if (older_senders) senders = BlockAmount(BlockAmount::Type::kOlder, *older_senders);
    if (older_tx_index) tx_index = BlockAmount(BlockAmount::Type::kOlder, *older_tx_index);
    if (older_call_traces) call_traces = BlockAmount(BlockAmount::Type::kOlder, *older_call_traces);

    // Apply discrete values for 'before' if provided
    if (before_history) history = BlockAmount(BlockAmount::Type::kBefore, *before_history);
    if (before_receipts) receipts = BlockAmount(BlockAmount::Type::kBefore, *before_receipts);
    if (before_senders) senders = BlockAmount(BlockAmount::Type::kBefore, *before_senders);
    if (before_tx_index) tx_index = BlockAmount(BlockAmount::Type::kBefore, *before_tx_index);
    if (before_call_traces) call_traces = BlockAmount(BlockAmount::Type::kBefore, *before_call_traces);

    if (!history) history = BlockAmount();
    if (!receipts) receipts = BlockAmount();
    if (!senders) senders = BlockAmount();
    if (!tx_index) tx_index = BlockAmount();
    if (!call_traces) call_traces = BlockAmount();

    return PruneMode(*history, *receipts, *senders, *tx_index, *call_traces);
}

}  // namespace silkworm::db
