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

namespace silkworm::db {
StorageMode read_storage_mode(mdbx::txn& txn) noexcept {
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

}  // namespace silkworm::db