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

//! \brief Holds the storage mode set
struct StorageMode {
    bool Initialized;  // Whether db storage has been initialized
    bool History;      // Whether history index is stored
    bool Receipts;     // Whether receipts are stored
    bool TxIndex;      // Whether tx_index is stored
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
    true,  // initialized
    true,  // history
    true,  // receipts
    true,  // tx_index
    true,  // call_traces
    false  // TEVM
};

// Keys for storage mode info from DbInfo bucket

constexpr const char* kStorageModeHistoryKey{"smHistory"};
constexpr const char* kStorageModeReceiptsKey{"smReceipts"};
constexpr const char* kStorageModeTxIndexKey{"smTxIndex"};
constexpr const char* kStorageModeCallTracesKey{"smCallTraces"};
constexpr const char* kStorageModeTEVMKey{"smTEVM"};

constexpr const char* kPruneModeHistoryKey{"pruneHistory"};
constexpr const char* kPruneModeReceiptsKey{"pruneReceipts"};
constexpr const char* kPruneModeTxIndexKey{"pruneTxIndex"};
constexpr const char* kPruneModeCallTracesKey{"pruneCallTraces"};

using PruneDistance = std::optional<BlockNum>;
constexpr BlockNum kDefaultPruneThreshold{90'000};

struct PruneMode {
    bool initialized{false};    // Whether db storage has been initialized
    PruneDistance history;      // Amount of blocks for history to keep in db
    PruneDistance receipts;     // Amount of blocks for receipts to keep in db
    PruneDistance tx_index;     // Amount of blocks for tx_index to keep in db
    PruneDistance call_traces;  // Amount of blocks for call_traces to keep in db

    [[nodiscard]] std::string to_string() const {
        if (!initialized) {
            return "default";
        }

        std::string short_form{"--prune="};
        std::string long_form{};

        if (history.has_value()) {
            if (history.value() == kDefaultPruneThreshold) {
                short_form += "h";
            } else {
                long_form += (" --prune.h.older=" + std::to_string(history.value()));
            }
        }

        if (receipts.has_value()) {
            if (receipts.value() == kDefaultPruneThreshold) {
                short_form += "r";
            } else {
                long_form += (" --prune.r.older=" + std::to_string(receipts.value()));
            }
        }

        if (tx_index.has_value()) {
            if (tx_index.value() == kDefaultPruneThreshold) {
                short_form += "t";
            } else {
                long_form += (" --prune.t.older=" + std::to_string(tx_index.value()));
            }
        }

        if (call_traces.has_value()) {
            if (call_traces.value() == kDefaultPruneThreshold) {
                short_form += "c";
            } else {
                long_form += (" --prune.c.older=" + std::to_string(call_traces.value()));
            }
        }

        return short_form + long_form;
    }

    bool operator==(const PruneMode& other) const {
        return history == other.history && receipts == other.receipts && tx_index == other.tx_index &&
               call_traces == other.call_traces;
    }
};

constexpr PruneMode kDefaultPruneMode{
    true,          // initialized
    std::nullopt,  // history
    std::nullopt,  // receipts
    std::nullopt,  // tx_index
    std::nullopt   // call_traces
};

//! \brief Reads storage mode from db
//! \param [in] txn : a db transaction
//! \return A StorageMode instance
StorageMode read_storage_mode(mdbx::txn& txn);

//! \brief Writes storage mode to db
//! \param [in] txn : a db transaction
//! \param [in] value : the StorageMode to be persisted
void write_storage_mode(mdbx::txn& txn, const StorageMode& value);

//! \brief Parses storage mode from a string
//! \param [in] mode : the string representation of StorageMode
StorageMode parse_storage_mode(std::string& mode);

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
PruneMode parse_prune_mode(std::string& mode, PruneDistance exactHistory = std::nullopt,
                           PruneDistance exactReceipts = std::nullopt, PruneDistance exactTxIndex = std::nullopt,
                           PruneDistance exactCallTraces = std::nullopt);

}  // namespace silkworm::db

#endif  // SILKWORM_STORAGE_HPP_
