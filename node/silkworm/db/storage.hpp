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

#pragma once
#ifndef SILKWORM_STORAGE_HPP_
#define SILKWORM_STORAGE_HPP_

#include "mdbx.hpp"
#include "tables.hpp"

namespace silkworm::db {

/// \brief Holds the storage mode set
struct StorageMode {
    bool Initialized;  // Whether db storage has been initialized
    bool History;      // Whether History index is stored
    bool Receipts;     // Whether Receipts are stored
    bool TxIndex;      // Whether TxIndex is stored
    bool CallTraces;   // Whether Call Traces are stored
    bool TEVM;         // TODO - not yet supported in Silkworm
    [[nodiscard]] std::string to_string() const {
        if (!Initialized) {
            return "default";
        }
        std::string ret{};
        if (History) {
            ret.push_back('h');
        }
        if (Receipts) {
            ret.push_back('r');
        }
        if (TxIndex) {
            ret.push_back('t');
        }
        if (CallTraces) {
            ret.push_back('c');
        }
        if (TEVM) {
            ret.push_back('e');
        }
        return ret;
    }

    bool operator==(const StorageMode& other) const {
        return History == other.History && Receipts == other.Receipts && TxIndex == other.TxIndex &&
               CallTraces == other.CallTraces && TEVM == other.TEVM;
    }
};

constexpr StorageMode kDefaultStorageMode{
    true,  // Initialized
    true,  // History
    true,  // Receipts
    true,  // TxIndex
    true,  // CallTraces
    false  // TEVM
};

// Keys for storage mode info from DbInfo bucket

constexpr const char* kStorageModeHistoryKey{"smHistory"};
constexpr const char* kStorageModeReceiptsKey{"smReceipts"};
constexpr const char* kStorageModeTxIndexKey{"smTxIndex"};
constexpr const char* kStorageModeCallTracesKey{"smCallTraces"};
constexpr const char* kStorageModeTEVMKey{"smTEVM"};

//! \brief Reads storage mode from db
//! \param [in] txn : a db transaction
//! \return A StorageMode instance
StorageMode read_storage_mode(mdbx::txn& txn) noexcept;

//! \brief Writes storage mode to db
//! \param [in] txn : a db transaction
//! \param [in] value : the StorageMode to be persisted
void write_storage_mode(mdbx::txn& txn, const StorageMode& value);

//! \brief Parses storage mode from a string
//! \param [in] mode : the string representation of StorageMode
StorageMode parse_storage_mode(std::string& mode);

}  // namespace silkworm::db

#endif  // SILKWORM_STORAGE_HPP_
