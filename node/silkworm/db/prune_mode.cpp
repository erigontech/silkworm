/*
    Copyright 2021-2022 The Silkworm Authors

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

#include "prune_mode.hpp"

#include <silkworm/common/endian.hpp>

namespace silkworm::db {

//! \brief Retrieves the proper BlockAmount prune threshold for given key
static BlockAmount read_block_amount_for_key(mdbx::cursor& source, const char* key) {
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
                    return BlockAmount();
                }
            } else if (data2.value.as_string() == "before") {
                value_type = BlockAmount::Type::kBefore;
            } else {
                // Something bad has been written
                throw std::runtime_error("Invalid prune type stored in database : " + data2.value.as_string());
            }
        }
        return BlockAmount(value_type, value);
    }
    return BlockAmount();
}

//! \brief Writes the BlockAmount keys in db
static void write_block_amount_for_key(mdbx::cursor& target, const char* key, const BlockAmount& block_amount) {
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
    if (!enabled_ || !value_) {
        return 0;
    }
    BlockNum tmpVal{value()};
    if (tmpVal >= stage_head) {
        return 0;
    }
    switch (type_) {
        case Type::kOlder:  // See Erigon prune mode Distance interface
            return stage_head - tmpVal;
        case Type::kBefore:  // See Erigon prune mode Before interface
            return tmpVal - 1;
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
    auto src{db::open_cursor(txn, table::kDatabaseInfo)};

    auto history{read_block_amount_for_key(src, kPruneModeHistoryKey)};
    auto receipts{read_block_amount_for_key(src, kPruneModeReceiptsKey)};
    auto senders{read_block_amount_for_key(src, kPruneModeSendersKey)};
    auto tx_index{read_block_amount_for_key(src, kPruneModeTxIndexKey)};
    auto call_traces{read_block_amount_for_key(src, kPruneModeCallTracesKey)};
    return PruneMode{history, receipts, senders, tx_index, call_traces};
}

void write_prune_mode(mdbx::txn& txn, const PruneMode& value) {
    auto target{db::open_cursor(txn, table::kDatabaseInfo)};
    write_block_amount_for_key(target, kPruneModeHistoryKey, value.history());
    write_block_amount_for_key(target, kPruneModeReceiptsKey, value.receipts());
    write_block_amount_for_key(target, kPruneModeSendersKey, value.senders());
    write_block_amount_for_key(target, kPruneModeTxIndexKey, value.tx_index());
    write_block_amount_for_key(target, kPruneModeCallTracesKey, value.call_traces());
}

std::unique_ptr<PruneMode> parse_prune_mode(const std::string& mode, const PruneDistance& olderHistory,
                                            const PruneDistance& olderReceipts, const PruneDistance& olderSenders,
                                            const PruneDistance& olderTxIndex, const PruneDistance& olderCallTraces,
                                            const PruneThreshold& beforeHistory, const PruneThreshold& beforeReceipts,
                                            const PruneThreshold& beforeSenders, const PruneThreshold& beforeTxIndex,
                                            const PruneThreshold& beforeCallTraces) {
    std::unique_ptr<BlockAmount> history, receipts, senders, tx_index, call_traces = std::make_unique<BlockAmount>();

    if (!mode.empty() && !(iequals(mode, "default") || iequals(mode, "disabled"))) {
        for (const auto& c : mode) {
            switch (c) {
                case 'h':
                    history = std::make_unique<BlockAmount>(BlockAmount::Type::kOlder, kFullImmutabilityThreshold);
                    break;
                case 'r':
                    receipts = std::make_unique<BlockAmount>(BlockAmount::Type::kOlder, kFullImmutabilityThreshold);
                    break;
                case 's':
                    senders = std::make_unique<BlockAmount>(BlockAmount::Type::kOlder, kFullImmutabilityThreshold);
                    break;
                case 't':
                    tx_index = std::make_unique<BlockAmount>(BlockAmount::Type::kOlder, kFullImmutabilityThreshold);
                    break;
                case 'c':
                    call_traces = std::make_unique<BlockAmount>(BlockAmount::Type::kOlder, kFullImmutabilityThreshold);
                    break;
                default:
                    throw std::invalid_argument("Invalid mode");
            }
        }
    }

    // Apply discrete values for 'older' if provided
    if (olderHistory.has_value()) history = std::make_unique<BlockAmount>(BlockAmount::Type::kOlder, *olderHistory);
    if (olderReceipts.has_value()) receipts = std::make_unique<BlockAmount>(BlockAmount::Type::kOlder, *olderReceipts);
    if (olderSenders.has_value()) senders = std::make_unique<BlockAmount>(BlockAmount::Type::kOlder, *olderSenders);
    if (olderTxIndex.has_value()) tx_index = std::make_unique<BlockAmount>(BlockAmount::Type::kOlder, *olderTxIndex);
    if (olderCallTraces.has_value())
        call_traces = std::make_unique<BlockAmount>(BlockAmount::Type::kOlder, *olderCallTraces);

    // Apply discrete values for 'before' if provided
    if (beforeHistory.has_value()) history = std::make_unique<BlockAmount>(BlockAmount::Type::kBefore, *beforeHistory);
    if (beforeReceipts.has_value())
        receipts = std::make_unique<BlockAmount>(BlockAmount::Type::kBefore, *beforeReceipts);
    if (beforeSenders.has_value()) senders = std::make_unique<BlockAmount>(BlockAmount::Type::kBefore, *beforeSenders);
    if (beforeTxIndex.has_value()) tx_index = std::make_unique<BlockAmount>(BlockAmount::Type::kBefore, *beforeTxIndex);
    if (beforeCallTraces.has_value())
        call_traces = std::make_unique<BlockAmount>(BlockAmount::Type::kBefore, *beforeCallTraces);

    if (!history) history = std::make_unique<BlockAmount>();
    if (!receipts) receipts = std::make_unique<BlockAmount>();
    if (!senders) senders = std::make_unique<BlockAmount>();
    if (!tx_index) tx_index = std::make_unique<BlockAmount>();
    if (!call_traces) call_traces = std::make_unique<BlockAmount>();

    return std::make_unique<PruneMode>(*history, *receipts, *senders, *tx_index, *call_traces);
}

}  // namespace silkworm::db