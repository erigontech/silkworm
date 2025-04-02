/*
   Copyright 2022 The Silkworm Authors

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

#include "util.hpp"

#include <cstring>
#include <stdexcept>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>

namespace silkworm::db {

using datastore::kvdb::from_slice;
using datastore::kvdb::to_slice;

Bytes storage_prefix(ByteView address, uint64_t incarnation) {
    SILKWORM_ASSERT(address.size() == kAddressLength || address.size() == kHashLength);
    Bytes res(address.size() + kIncarnationLength, '\0');
    std::memcpy(&res[0], address.data(), address.size());
    endian::store_big_u64(&res[address.size()], incarnation);
    return res;
}

Bytes storage_prefix(const evmc::address& address, uint64_t incarnation) {
    return storage_prefix(address.bytes, incarnation);
}

Bytes composite_storage_key(const evmc::address& address, uint64_t incarnation, HashAsArray hash) {
    Bytes res(kAddressLength + kIncarnationLength + kHashLength, '\0');
    std::memcpy(&res[0], address.bytes, kAddressLength);
    endian::store_big_u64(&res[kAddressLength], incarnation);
    std::memcpy(&res[kAddressLength + db::kIncarnationLength], hash, kHashLength);
    return res;
}

Bytes block_key(BlockNum block_num) {
    Bytes key(sizeof(BlockNum), '\0');
    endian::store_big_u64(&key[0], block_num);
    return key;
}

Bytes block_key(BlockNum block_num, std::span<const uint8_t, kHashLength> hash) {
    Bytes key(sizeof(BlockNum) + kHashLength, '\0');
    endian::store_big_u64(&key[0], block_num);
    std::memcpy(&key[8], hash.data(), kHashLength);
    return key;
}

std::tuple<BlockNum, evmc::bytes32> split_block_key(ByteView key) {
    SILKWORM_ASSERT(key.size() == sizeof(BlockNum) + kHashLength);

    ByteView block_num_part = key.substr(0, sizeof(BlockNum));
    BlockNum block_num = endian::load_big_u64(block_num_part.data());

    ByteView hash_part = key.substr(sizeof(BlockNum));
    evmc::bytes32 hash;
    std::memcpy(hash.bytes, hash_part.data(), hash_part.size());

    return {block_num, hash};
}

Bytes storage_change_key(BlockNum block_num, const evmc::address& address, uint64_t incarnation) {
    Bytes res(sizeof(BlockNum) + kPlainStoragePrefixLength, '\0');
    endian::store_big_u64(&res[0], block_num);
    std::memcpy(&res[8], address.bytes, kAddressLength);
    endian::store_big_u64(&res[8 + kAddressLength], incarnation);
    return res;
}

Bytes account_history_key(const evmc::address& address, BlockNum block_num) {
    Bytes res(kAddressLength + sizeof(BlockNum), '\0');
    std::memcpy(&res[0], address.bytes, kAddressLength);
    endian::store_big_u64(&res[kAddressLength], block_num);
    return res;
}

Bytes storage_history_key(const evmc::address& address, const evmc::bytes32& location, BlockNum block_num) {
    Bytes res(kAddressLength + kHashLength + sizeof(BlockNum), '\0');
    std::memcpy(&res[0], address.bytes, kAddressLength);
    std::memcpy(&res[kAddressLength], location.bytes, kHashLength);
    endian::store_big_u64(&res[kAddressLength + kHashLength], block_num);
    return res;
}

Bytes log_key(BlockNum block_num, uint32_t transaction_id) {
    Bytes key(sizeof(BlockNum) + sizeof(uint32_t), '\0');
    endian::store_big_u64(&key[0], block_num);
    endian::store_big_u32(&key[8], transaction_id);
    return key;
}

Bytes log_address_key(const evmc::address& address, BlockNum block_num) {
    SILKWORM_ASSERT(block_num <= std::numeric_limits<uint32_t>::max());
    Bytes key(kAddressLength + sizeof(uint32_t), '\0');
    std::memcpy(key.data(), address.bytes, kAddressLength);
    endian::store_big_u32(key.data() + kAddressLength, static_cast<uint32_t>(block_num));
    return key;
}

Bytes log_topic_key(const evmc::bytes32& topic, BlockNum block_num) {
    SILKWORM_ASSERT(block_num <= std::numeric_limits<uint32_t>::max());
    Bytes key(kHashLength + sizeof(uint32_t), '\0');
    std::memcpy(key.data(), topic.bytes, kHashLength);
    endian::store_big_u32(key.data() + kHashLength, static_cast<uint32_t>(block_num));
    return key;
}

BlockNum block_num_from_key(const mdbx::slice& key) {
    SILKWORM_ASSERT(key.size() >= sizeof(BlockNum));
    ByteView key_view{from_slice(key)};
    return endian::load_big_u64(key_view.data());
}

std::tuple<BlockNum, uint32_t> split_log_key(const mdbx::slice& key) {
    SILKWORM_ASSERT(key.size() == sizeof(BlockNum) + sizeof(uint32_t));
    ByteView key_view{from_slice(key)};
    return {endian::load_big_u64(key_view.data()), endian::load_big_u32(key_view.data() + sizeof(BlockNum))};
}

std::tuple<ByteView, uint32_t> split_log_address_key(const mdbx::slice& key) {
    SILKWORM_ASSERT(key.size() == kAddressLength + sizeof(uint32_t));
    ByteView key_view{from_slice(key)};
    return {key_view.substr(0, kAddressLength), endian::load_big_u32(key_view.data() + kAddressLength)};
}

std::tuple<ByteView, uint32_t> split_log_topic_key(const mdbx::slice& key) {
    SILKWORM_ASSERT(key.size() == kHashLength + sizeof(uint32_t));
    ByteView key_view{from_slice(key)};
    return {key_view.substr(0, kHashLength), endian::load_big_u32(key_view.data() + kHashLength)};
}

std::pair<Bytes, Bytes> changeset_to_plainstate_format(const ByteView key, ByteView value) {
    if (key.size() == sizeof(BlockNum)) {
        if (value.size() < kAddressLength) {
            throw std::runtime_error("Invalid value length " + std::to_string(value.size()) +
                                     " for account changeset in " + std::string(__FUNCTION__));
        }
        // AccountChangeSet
        const Bytes address{value.substr(0, kAddressLength)};
        const Bytes previous_value{value.substr(kAddressLength)};
        return {address, previous_value};
    }
    if (key.size() == sizeof(BlockNum) + kPlainStoragePrefixLength) {
        if (value.size() < kHashLength) {
            throw std::runtime_error("Invalid value length " + std::to_string(value.size()) +
                                     " for storage changeset in " + std::string(__FUNCTION__));
        }

        // StorageChangeSet See storage_change_key
        Bytes full_key(kPlainStoragePrefixLength + kHashLength, '\0');
        std::memcpy(&full_key[0], &key[8], kPlainStoragePrefixLength);
        std::memcpy(&full_key[kPlainStoragePrefixLength], &value[0], kHashLength);
        value.remove_prefix(kHashLength);
        return {full_key, Bytes(value)};
    }
    throw std::runtime_error("Invalid key length " + std::to_string(key.size()) + " in " + std::string(__FUNCTION__));
}

std::optional<ByteView> find_value_suffix(datastore::kvdb::ROCursorDupSort& table, ByteView key, ByteView value_prefix) {
    auto value_prefix_slice{to_slice(value_prefix)};
    auto data{table.lower_bound_multivalue(to_slice(key), value_prefix_slice, /*throw_notfound=*/false)};
    if (!data || !data.value.starts_with(value_prefix_slice)) {
        return std::nullopt;
    }

    ByteView res{from_slice(data.value)};
    res.remove_prefix(value_prefix.size());
    return res;
}

void upsert_storage_value(datastore::kvdb::RWCursorDupSort& state_cursor, ByteView storage_prefix, ByteView location, ByteView new_value) {
    if (find_value_suffix(state_cursor, storage_prefix, location)) {
        state_cursor.erase();
    }
    new_value = zeroless_view(new_value);
    if (!new_value.empty()) {
        Bytes new_db_value(location.size() + new_value.size(), '\0');
        std::memcpy(&new_db_value[0], location.data(), location.size());
        std::memcpy(&new_db_value[location.size()], new_value.data(), new_value.size());
        state_cursor.upsert(to_slice(storage_prefix), to_slice(new_db_value));
    }
}

Bytes account_domain_key(const evmc::address& address) {
    return {address.bytes, kAddressLength};
}

Bytes storage_domain_key(const evmc::address& address, const evmc::bytes32& location) {
    Bytes key(kAddressLength + kHashLength, '\0');
    std::memcpy(key.data(), address.bytes, kAddressLength);
    std::memcpy(key.data() + kAddressLength, location.bytes, kHashLength);
    return key;
}

Bytes code_domain_key(const evmc::address& address) {
    return {address.bytes, kAddressLength};
}

Bytes topic_domain_key(const evmc::bytes32& topic) {
    return {topic.bytes, sizeof(topic.bytes)};
}

}  // namespace silkworm::db
