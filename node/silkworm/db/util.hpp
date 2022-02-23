/*
   Copyright 2020-2022 The Silkworm Authors

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

#include <silkworm/common/base.hpp>
#include <silkworm/db/mdbx.hpp>
#include <silkworm/types/block.hpp>

namespace silkworm::db {

/* Ancillary entities */

// Used to compare versions of entities (e.g. DbSchema)
struct VersionBase {
    uint32_t Major;
    uint32_t Minor;
    uint32_t Patch;
    [[nodiscard]] std::string to_string() const {
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

/* Common Keys */

// Key for DbInfo bucket storing db schema version
inline constexpr const char* kDbSchemaVersionKey{"dbVersion"};

inline constexpr size_t kIncarnationLength{8};
inline constexpr size_t kLocationLength{32};
static_assert(kIncarnationLength == sizeof(uint64_t));
static_assert(kLocationLength == sizeof(evmc::bytes32));

inline constexpr size_t kPlainStoragePrefixLength{kAddressLength + kIncarnationLength};
inline constexpr size_t kHashedStoragePrefixLength{kHashLength + kIncarnationLength};

// address -> storage-encoded initial value
using AccountChanges = absl::btree_map<evmc::address, Bytes>;

// address -> incarnation -> location -> zeroless initial value
using StorageChanges = absl::btree_map<evmc::address, absl::btree_map<uint64_t, absl::btree_map<evmc::bytes32, Bytes>>>;

// Erigon GenerateStoragePrefix, PlainGenerateStoragePrefix
// address can be either plain account address (20 bytes) or hash thereof (32 bytes)
Bytes storage_prefix(ByteView address, uint64_t incarnation);

// Erigon EncodeBlockNumber
Bytes block_key(BlockNum block_number);

// Erigon HeaderKey & BlockBodyKey
Bytes block_key(BlockNum block_number, const uint8_t (&hash)[kHashLength]);

Bytes storage_change_key(BlockNum block_number, const evmc::address& address, uint64_t incarnation);

// Erigon IndexChunkKey for account
Bytes account_history_key(const evmc::address& address, BlockNum block_number);

// Erigon IndexChunkKey for storage
Bytes storage_history_key(const evmc::address& address, const evmc::bytes32& location, BlockNum block_number);

// Erigon LogKey
Bytes log_key(BlockNum block_number, uint32_t transaction_id);

//! \brief Converts change set (AccountChangeSet/StorageChangeSet) entry to plain state format.
//! \param [in] key : Change set key.
//! \param [in] value : Change set value.
//! \return Plain state key + previous value of the account or storage.
//! \remarks For storage location is returned as the last part of the key,
//! while technically in PlainState it's the first part of the value.
std::pair<Bytes, Bytes> changeset_to_plainstate_format(ByteView key, ByteView value);

inline mdbx::slice to_slice(ByteView value) { return {value.data(), value.length()}; }

inline ByteView from_slice(const mdbx::slice slice) {
    return {static_cast<const uint8_t*>(slice.data()), slice.length()};
}

// If there exists an entry in a multivalue table with a given key and a value starting with a given prefix,
// return the suffix of the value.
// Otherwise, return nullopt.
std::optional<ByteView> find_value_suffix(mdbx::cursor& table, ByteView key, ByteView value_prefix);

// We can't simply call upsert for storage values because they live in mdbx::value_mode::multi tables
void upsert_storage_value(mdbx::cursor& state_cursor, ByteView storage_prefix, ByteView location, ByteView new_value);

namespace detail {

    // See Erigon BodyForStorage
    struct BlockBodyForStorage {
        uint64_t base_txn_id{0};
        uint64_t txn_count{0};
        std::vector<BlockHeader> ommers;

        [[nodiscard]] Bytes encode() const;
    };

    BlockBodyForStorage decode_stored_block_body(ByteView& from);

}  // namespace detail
}  // namespace silkworm::db

#endif  // SILKWORM_DB_UTIL_HPP_
