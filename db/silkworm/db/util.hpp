/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_DB_UTIL_HPP_
#define SILKWORM_DB_UTIL_HPP_

/*
Part of the compatibility layer with the Erigon DB format;
see its package dbutils.
*/

#include <string>

#include <absl/container/btree_map.h>
#include <mdbx.h++>

#include <silkworm/common/base.hpp>
#include <silkworm/types/block.hpp>

namespace silkworm::db {

/* Ancillary entities */

// Used to compare versions of entities (eg. DbSchema)
struct VersionBase {
    uint32_t Major;
    uint32_t Minor;
    uint32_t Patch;
    std::string to_string() {
        std::string ret{std::to_string(Major)};
        ret.append("." + std::to_string(Minor));
        ret.append("." + std::to_string(Patch));
        return ret;
    }
    bool operator==(const VersionBase& other) const {
        return Major == other.Major && Minor == other.Minor && Patch == other.Patch;
    }
    bool operator!=(const VersionBase& other) const { return !(this->operator==(other)); }
    bool operator<(const VersionBase& other) const {
        if (Major < other.Major) {
            return true;
        } else if (Major == other.Major) {
            if (Minor < other.Minor) {
                return true;
            } else if (Minor == other.Minor) {
                if (Patch < other.Patch) {
                    return true;
                }
            }
        }
        return false;
    }
    bool operator>(const VersionBase& other) const {
        if (Major > other.Major) {
            return true;
        } else if (Major == other.Major) {
            if (Minor > other.Minor) {
                return true;
            } else if (Minor == other.Minor) {
                if (Patch > other.Patch) {
                    return true;
                }
            }
        }
        return false;
    }
    bool operator<=(const VersionBase& other) const { return this->operator==(other) || this->operator<(other); }
    bool operator>=(const VersionBase& other) const { return this->operator==(other) || this->operator>(other); }
};

// Holds the storage mode set
struct StorageMode {
    bool Initialized;  // Whether or not db storage has been initialized
    bool History;      // Whether or not History index is stored
    bool Receipts;     // Whether or not Receipts are stored
    bool TxIndex;      // Whether or not TxIndex is stored
    bool CallTraces;   // Whether or not Call Traces are stored
    bool TEVM;         // TODO - not yet supported in Silkworm
    std::string to_string() const {
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
    /*Initialized*/ true, /*History*/ true,    /*Receipts*/ true,
    /*TxIndex*/ true,     /*CallTraces*/ true, /*TEVM*/ false,
};

/* Common Keys */

// Key for DbInfo bucket storing db schema version
constexpr const char* kDbSchemaVersionKey{"dbVersion"};

// Keys for storage mode info from DbInfo bucket
constexpr const char* kStorageModeHistoryKey{"smHistory"};
constexpr const char* kStorageModeReceiptsKey{"smReceipts"};
constexpr const char* kStorageModeTxIndexKey{"smTxIndex"};
constexpr const char* kStorageModeCallTracesKey{"smCallTraces"};
constexpr const char* kStorageModeTEVMKey{"smTEVM"};

constexpr size_t kIncarnationLength{8};
static_assert(kIncarnationLength == sizeof(uint64_t));

constexpr size_t kStoragePrefixLength{kAddressLength + kIncarnationLength};

// address -> storage-encoded initial value
using AccountChanges = absl::btree_map<evmc::address, Bytes>;

// address -> incarnation -> location -> zeroless initial value
using StorageChanges = absl::btree_map<evmc::address, absl::btree_map<uint64_t, absl::btree_map<evmc::bytes32, Bytes>>>;

// Erigon GenerateStoragePrefix, PlainGenerateStoragePrefix
// address can be either plain account address (20 bytes) or hash thereof (32 bytes)
Bytes storage_prefix(ByteView address, uint64_t incarnation);

// Erigon CanonicalHeadersKey / ReceiptsKey
Bytes block_key(uint64_t block_number);

// Erigon HeaderKey & BlockBodyKey
Bytes block_key(uint64_t block_number, const uint8_t (&hash)[kHashLength]);

Bytes storage_change_key(uint64_t block_number, const evmc::address& address, uint64_t incarnation);

// Erigon IndexChunkKey for account
Bytes account_history_key(const evmc::address& address, uint64_t block_number);

// Erigon IndexChunkKey for storage
Bytes storage_history_key(const evmc::address& address, const evmc::bytes32& location, uint64_t block_number);

// Erigon LogKey
Bytes log_key(uint64_t block_number, uint32_t transaction_id);

inline mdbx::slice to_slice(ByteView value) {
    return mdbx::slice(static_cast<const void*>(value.data()), value.length());
}

inline mdbx::slice to_slice(const evmc::address& value) {
    return mdbx::slice(static_cast<const void*>(value.bytes), sizeof(evmc::address));
}

inline mdbx::slice to_slice(const evmc::bytes32& value) {
    return mdbx::slice(static_cast<const void*>(value.bytes), sizeof(evmc::bytes32));
}

inline ByteView from_slice(const mdbx::slice slice) { return {static_cast<uint8_t*>(slice.iov_base), slice.iov_len}; }

// If there exists an entry in a multivalue table with a given key and a value starting with a given prefix,
// return the suffix of the value.
// Otherwise, return nullopt.
std::optional<ByteView> find_value_suffix(mdbx::cursor& table, ByteView key, ByteView value_prefix);

namespace detail {

    // See Erigon BodyForStorage
    struct BlockBodyForStorage {
        uint64_t base_txn_id{0};
        uint64_t txn_count{0};
        std::vector<BlockHeader> ommers;

        Bytes encode() const;
    };

    BlockBodyForStorage decode_stored_block_body(ByteView& from);

}  // namespace detail
}  // namespace silkworm::db

#endif  // SILKWORM_DB_UTIL_HPP_
