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

#include <silkworm/common/base.hpp>
#include <silkworm/types/block.hpp>

#include "../libmdbx/mdbx.h++"

namespace silkworm::db {

constexpr size_t kIncarnationLength{8};
static_assert(kIncarnationLength == sizeof(uint64_t));

constexpr size_t kStoragePrefixLength{kAddressLength + kIncarnationLength};

struct Entry {
    ByteView key;
    ByteView value;
};

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

// Default database path
std::string default_path();

inline ByteView from_iovec(const iovec val) {
    auto* ptr{static_cast<uint8_t*>(val.iov_base)};
    return {ptr, val.iov_len};
}

inline mdbx::slice to_slice(ByteView view) { return mdbx::slice(static_cast<const void*>(view.data()), view.length()); }

inline ByteView from_slice(const mdbx::slice slice) { return {slice.byte_ptr(), slice.length()}; }

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
