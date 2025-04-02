// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

/*
Part of the compatibility layer with the Erigon DB format;
see its package dbutils.
*/

#include <compare>
#include <span>
#include <string>

#include <absl/container/btree_map.h>
#include <absl/strings/str_cat.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>

namespace silkworm::db {

/* Ancillary entities */

// Used to compare versions of entities (e.g. DbSchema)
struct VersionBase {
    uint32_t major{0};
    uint32_t minor{0};
    uint32_t patch{0};

    std::string to_string() const { return absl::StrCat(major, ".", minor, ".", patch); }

    // NOLINTNEXTLINE(hicpp-use-nullptr, modernize-use-nullptr)
    friend auto operator<=>(const VersionBase&, const VersionBase&) = default;
};

/* Common Keys */

//! Key for DbInfo bucket storing db schema version
inline constexpr std::string_view kDbSchemaVersionKey{"dbVersion"};

//! Key for Sequence bucket storing state version
inline constexpr std::string_view kPlainStateVersionKey{"PlainStateVersion"};

inline constexpr size_t kIncarnationLength{8};
inline constexpr size_t kLocationLength{32};
static_assert(kIncarnationLength == sizeof(uint64_t));
static_assert(kLocationLength == sizeof(evmc::bytes32));

inline constexpr size_t kPlainStoragePrefixLength{kAddressLength + kIncarnationLength};
inline constexpr size_t kHashedStoragePrefixLength{kHashLength + kIncarnationLength};

// address -> storage-encoded initial value
using AccountChanges = absl::btree_map<evmc::address, Bytes>;

// address -> incarnation -> location -> zeroless initial value
using ChangedLocations = absl::btree_map<evmc::bytes32, Bytes>;
using ChangedIncarnations = absl::btree_map<uint64_t, ChangedLocations>;
using StorageChanges = absl::btree_map<evmc::address, ChangedIncarnations>;

// Erigon GenerateStoragePrefix, PlainGenerateStoragePrefix
// address can be either plain account address (20 bytes) or hash thereof (32 bytes)
Bytes storage_prefix(ByteView address, uint64_t incarnation);

Bytes storage_prefix(const evmc::address& address, uint64_t incarnation);

Bytes composite_storage_key(const evmc::address& address, uint64_t incarnation, HashAsArray hash);

// Erigon EncodeBlockNumber
Bytes block_key(BlockNum block_num);

// Erigon HeaderKey & BlockBodyKey
Bytes block_key(BlockNum block_num, std::span<const uint8_t, kHashLength> hash);

// Split a block key in BlockNum and Hash
std::tuple<BlockNum, evmc::bytes32> split_block_key(ByteView key);

Bytes storage_change_key(BlockNum block_num, const evmc::address& address, uint64_t incarnation);

// Erigon IndexChunkKey for account
Bytes account_history_key(const evmc::address& address, BlockNum block_num);

// Erigon IndexChunkKey for storage
Bytes storage_history_key(const evmc::address& address, const evmc::bytes32& location, BlockNum block_num);

// Erigon LogKey
Bytes log_key(BlockNum block_num, uint32_t transaction_id);

//! Encode LogAddressIndex table key for target address
Bytes log_address_key(const evmc::address& address, BlockNum block_num);

//! Encode LogTopicIndex table key for target topic
Bytes log_topic_key(const evmc::bytes32& topic, BlockNum block_num);

BlockNum block_num_from_key(const mdbx::slice& key);

//! Decode TransactionLog table key into block number and transaction index
std::tuple<BlockNum, uint32_t> split_log_key(const mdbx::slice& key);

//! Decode LogAddressIndex table key into account address and block upper bound
std::tuple<ByteView, uint32_t> split_log_address_key(const mdbx::slice& key);

//! Decode LogTopicIndex table key into topic hash and block upper bound
std::tuple<ByteView, uint32_t> split_log_topic_key(const mdbx::slice& key);

//! \brief Converts change set (AccountChangeSet/StorageChangeSet) entry to plain state format.
//! \param [in] key : Change set key.
//! \param [in] value : Change set value.
//! \return Plain state key + previous value of the account or storage.
//! \remarks For storage location is returned as the last part of the key,
//! while technically in PlainState it's the first part of the value.
std::pair<Bytes, Bytes> changeset_to_plainstate_format(ByteView key, ByteView value);

inline mdbx::slice to_slice(const evmc::bytes32& value) {
    return datastore::kvdb::to_slice(ByteView{value.bytes});
}

inline mdbx::slice to_slice(const evmc::address& address) {
    return datastore::kvdb::to_slice(ByteView{address.bytes});
}

// If there exists an entry in a multivalue table with a given key and a value starting with a given prefix,
// return the suffix of the value.
// Otherwise, return nullopt.
std::optional<ByteView> find_value_suffix(datastore::kvdb::ROCursorDupSort& table, ByteView key, ByteView value_prefix);

// We can't simply call upsert for storage values because they live in mdbx::value_mode::multi tables
void upsert_storage_value(datastore::kvdb::RWCursorDupSort& state_cursor, ByteView storage_prefix, ByteView location, ByteView new_value);

//! Build key for account domain given the target address and location
Bytes account_domain_key(const evmc::address& address);

//! Build key for storage domain given the target address and location
Bytes storage_domain_key(const evmc::address& address, const evmc::bytes32& location);

//! Build key for code domain given the target address and location
Bytes code_domain_key(const evmc::address& address);

//! Build key for topic domain given the target topic
Bytes topic_domain_key(const evmc::bytes32& topic);
}  // namespace silkworm::db
