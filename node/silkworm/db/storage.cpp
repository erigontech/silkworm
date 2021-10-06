/*
Copyright 2021 The Silkworm Authors

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

#include "storage.hpp"

#include <silkworm/common/endian.hpp>

namespace silkworm::db {
StorageMode read_storage_mode(mdbx::txn& txn) {
    StorageMode ret{true};
    auto src{db::open_cursor(txn, table::kDatabaseInfo)};

    // History
    auto data{src.find(mdbx::slice{kStorageModeHistoryKey}, /*throw_notfound*/ false)};
    ret.History = (data.done && data.value.length() == 1 && data.value.at(0) == 1);

    // Receipts
    data = src.find(mdbx::slice{kStorageModeReceiptsKey}, /*throw_notfound*/ false);
    ret.Receipts = (data.done && data.value.length() == 1 && data.value.at(0) == 1);

    // TxIndex
    data = src.find(mdbx::slice{kStorageModeTxIndexKey}, /*throw_notfound*/ false);
    ret.TxIndex = (data.done && data.value.length() == 1 && data.value.at(0) == 1);

    // Call Traces
    data = src.find(mdbx::slice{kStorageModeCallTracesKey}, /*throw_notfound*/ false);
    ret.CallTraces = (data.done && data.value.length() == 1 && data.value.at(0) == 1);

    // TEVM
    data = src.find(mdbx::slice{kStorageModeTEVMKey}, /*throw_notfound*/ false);
    ret.TEVM = (data.done && data.value.length() == 1 && data.value.at(0) == 1);

    return ret;
}

void write_storage_mode(mdbx::txn& txn, const StorageMode& val) {
    auto target{db::open_cursor(txn, table::kDatabaseInfo)};
    Bytes v_on(1, '\1');
    Bytes v_off(2, '\0');

    target.upsert(mdbx::slice{kStorageModeHistoryKey}, to_slice(val.History ? v_on : v_off));
    target.upsert(mdbx::slice{kStorageModeReceiptsKey}, to_slice(val.Receipts ? v_on : v_off));
    target.upsert(mdbx::slice{kStorageModeTxIndexKey}, to_slice(val.TxIndex ? v_on : v_off));
    target.upsert(mdbx::slice{kStorageModeCallTracesKey}, to_slice(val.CallTraces ? v_on : v_off));
    target.upsert(mdbx::slice{kStorageModeTEVMKey}, to_slice(val.TEVM ? v_on : v_off));
}

StorageMode parse_storage_mode(std::string& mode) {
    if (mode == "default") {
        return kDefaultStorageMode;
    }
    StorageMode ret{/*Initialized*/ true};
    for (auto& c : mode) {
        switch (c) {
            case 'h':
                ret.History = true;
                break;
            case 'r':
                ret.Receipts = true;
                break;
            case 't':
                ret.TxIndex = true;
                break;
            case 'c':
                ret.CallTraces = true;
                break;
            case 'e':
                ret.TEVM = true;
                break;
            default:
                throw std::invalid_argument("Invalid mode");
        }
    }
    return ret;
}

PruneMode read_prune_mode(mdbx::txn& txn) {
    PruneMode ret{true};
    auto src{db::open_cursor(txn, table::kDatabaseInfo)};

    /*
     * TODO Eventually optimize with removal of keys which don't prune at all
     * For compatibility reasons with Erigon we assume a value == UINT64_MAX means no pruning
     */

    // History
    auto data{src.find(mdbx::slice{kPruneModeHistoryKey}, /*throw_notfound=*/false)};
    if (data.done) {
        assert(data.value.length() == sizeof(uint64_t));
        auto value{endian::load_big_u64(from_slice(data.value).data())};
        if (value != UINT64_MAX) {
            ret.history.emplace(value);
        }
    }

    // Receipts
    data = src.find(mdbx::slice{kPruneModeReceiptsKey}, /*throw_notfound=*/false);
    if (data.done) {
        assert(data.value.length() == sizeof(uint64_t));
        auto value{endian::load_big_u64(from_slice(data.value).data())};
        if (value != UINT64_MAX) {
            ret.receipts.emplace(value);
        }
    }

    // TxIndex
    data = src.find(mdbx::slice{kPruneModeTxIndexKey}, /*throw_notfound=*/false);
    if (data.done) {
        assert(data.value.length() == sizeof(uint64_t));
        auto value{endian::load_big_u64(from_slice(data.value).data())};
        if (value != UINT64_MAX) {
            ret.tx_index.emplace(value);
        }
    }

    // CallTraces
    data = src.find(mdbx::slice{kPruneModeCallTracesKey}, /*throw_notfound=*/false);
    if (data.done) {
        assert(data.value.length() == sizeof(uint64_t));
        auto value{endian::load_big_u64(from_slice(data.value).data())};
        if (value != UINT64_MAX) {
            ret.call_traces.emplace(value);
        }
    }

    return ret;
}

void write_prune_mode(mdbx::txn& txn, const PruneMode& value) {
    auto target{db::open_cursor(txn, table::kDatabaseInfo)};
    Bytes db_value(sizeof(BlockNum), '\0');

    // History
    if (value.history.has_value()) {
        endian::store_big_u64(db_value.data(), value.history.value());
        target.upsert(mdbx::slice(kPruneModeHistoryKey), to_slice(db_value));
    } else {
        target.erase(mdbx::slice(kPruneModeHistoryKey));
    }

    // Receipts
    if (value.receipts.has_value()) {
        endian::store_big_u64(db_value.data(), value.receipts.value());
        target.upsert(mdbx::slice(kPruneModeReceiptsKey), to_slice(db_value));
    } else {
        target.erase(mdbx::slice(kPruneModeReceiptsKey));
    }

    // TxIndex
    if (value.tx_index.has_value()) {
        endian::store_big_u64(db_value.data(), value.tx_index.value());
        target.upsert(mdbx::slice(kPruneModeTxIndexKey), to_slice(db_value));
    } else {
        target.erase(mdbx::slice(kPruneModeTxIndexKey));
    }

    // Call Traces
    if (value.call_traces.has_value()) {
        endian::store_big_u64(db_value.data(), value.call_traces.value());
        target.upsert(mdbx::slice(kPruneModeCallTracesKey), to_slice(db_value));
    } else {
        target.erase(mdbx::slice(kPruneModeCallTracesKey));
    }

}

PruneMode parse_prune_mode(std::string& mode, PruneDistance exactHistory, PruneDistance exactReceipts,
                           PruneDistance exactTxIndex, PruneDistance exactCallTraces) {
    PruneMode ret{kDefaultPruneMode};
    if (!mode.empty() && !(iequals(mode, "default") || iequals(mode, "disabled"))) {
        for (const auto& c : mode) {
            switch (c) {
                case 'h':
                    ret.history.emplace(kDefaultPruneThreshold);
                    break;
                case 'r':
                    ret.receipts.emplace(kDefaultPruneThreshold);
                    break;
                case 't':
                    ret.tx_index.emplace(kDefaultPruneThreshold);
                    break;
                case 'c':
                    ret.call_traces.emplace(kDefaultPruneThreshold);
                    break;
                default:
                    throw std::invalid_argument("Invalid mode");
            }
        }
    }
    // Apply discrete values if provided
    if (exactHistory.has_value()) ret.history = exactHistory;
    if (exactReceipts.has_value()) ret.receipts = exactReceipts;
    if (exactTxIndex.has_value()) ret.tx_index = exactTxIndex;
    if (exactCallTraces.has_value()) ret.call_traces = exactCallTraces;

    return ret;
}

}  // namespace silkworm::db