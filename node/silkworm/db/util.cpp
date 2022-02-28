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

#include "util.hpp"

#include <cstring>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/rlp_err.hpp>
#include <silkworm/rlp/encode_vector.hpp>

namespace silkworm::db {

Bytes storage_prefix(ByteView address, uint64_t incarnation) {
    SILKWORM_ASSERT(address.length() == kAddressLength || address.length() == kHashLength);
    Bytes res(address.length() + kIncarnationLength, '\0');
    std::memcpy(&res[0], address.data(), address.length());
    endian::store_big_u64(&res[address.length()], incarnation);
    return res;
}

Bytes block_key(BlockNum block_number) {
    Bytes key(8, '\0');
    endian::store_big_u64(&key[0], block_number);
    return key;
}

Bytes block_key(BlockNum block_number, const uint8_t (&hash)[kHashLength]) {
    Bytes key(8 + kHashLength, '\0');
    endian::store_big_u64(&key[0], block_number);
    std::memcpy(&key[8], hash, kHashLength);
    return key;
}

Bytes storage_change_key(BlockNum block_number, const evmc::address& address, uint64_t incarnation) {
    Bytes res(8 + kPlainStoragePrefixLength, '\0');
    endian::store_big_u64(&res[0], block_number);
    std::memcpy(&res[8], address.bytes, kAddressLength);
    endian::store_big_u64(&res[8 + kAddressLength], incarnation);
    return res;
}

Bytes account_history_key(const evmc::address& address, BlockNum block_number) {
    Bytes res(kAddressLength + 8, '\0');
    std::memcpy(&res[0], address.bytes, kAddressLength);
    endian::store_big_u64(&res[kAddressLength], block_number);
    return res;
}

Bytes storage_history_key(const evmc::address& address, const evmc::bytes32& location, BlockNum block_number) {
    Bytes res(kAddressLength + kHashLength + 8, '\0');
    std::memcpy(&res[0], address.bytes, kAddressLength);
    std::memcpy(&res[kAddressLength], location.bytes, kHashLength);
    endian::store_big_u64(&res[kAddressLength + kHashLength], block_number);
    return res;
}

Bytes log_key(BlockNum block_number, uint32_t transaction_id) {
    Bytes key(8 + 4, '\0');
    endian::store_big_u64(&key[0], block_number);
    endian::store_big_u32(&key[8], transaction_id);
    return key;
}

std::pair<Bytes, Bytes> changeset_to_plainstate_format(const ByteView key, ByteView value) {
    if (key.size() == 8) {
        if (value.length() < kAddressLength) {
            throw std::runtime_error("Invalid value length " + std::to_string(value.length()) +
                                     " for account changeset in " + std::string(__FUNCTION__));
        }
        // AccountChangeSet
        const Bytes address{value.substr(0, kAddressLength)};
        const Bytes previous_value{value.substr(kAddressLength)};
        return {address, previous_value};
    } else if (key.length() == 8 + kPlainStoragePrefixLength) {
        if (value.length() < kHashLength) {
            throw std::runtime_error("Invalid value length " + std::to_string(value.length()) +
                                     " for storage changeset in " + std::string(__FUNCTION__));
        }

        // StorageChangeSet See storage_change_key
        Bytes full_key(kPlainStoragePrefixLength + kHashLength, '\0');
        std::memcpy(&full_key[0], &key[8], kPlainStoragePrefixLength);
        std::memcpy(&full_key[kPlainStoragePrefixLength], &value[0], kHashLength);
        value.remove_prefix(kHashLength);
        return {full_key, Bytes(value)};
    }
    throw std::runtime_error("Invalid key length " + std::to_string(key.length()) + " in " + std::string(__FUNCTION__));
}

std::optional<ByteView> find_value_suffix(mdbx::cursor& table, ByteView key, ByteView value_prefix) {
    auto value_prefix_slice{to_slice(value_prefix)};
    auto data{table.lower_bound_multivalue(to_slice(key), value_prefix_slice, /*throw_notfound=*/false)};
    if (!data || !data.value.starts_with(value_prefix_slice)) {
        return std::nullopt;
    }

    ByteView res{from_slice(data.value)};
    res.remove_prefix(value_prefix.length());
    return res;
}

void upsert_storage_value(mdbx::cursor& state_cursor, ByteView storage_prefix, ByteView location, ByteView new_value) {
    if (find_value_suffix(state_cursor, storage_prefix, location)) {
        state_cursor.erase();
    }
    new_value = zeroless_view(new_value);
    if (!new_value.empty()) {
        Bytes new_db_value(location.length() + new_value.length(), '\0');
        std::memcpy(&new_db_value[0], location.data(), location.length());
        std::memcpy(&new_db_value[location.length()], new_value.data(), new_value.length());
        state_cursor.upsert(to_slice(storage_prefix), to_slice(new_db_value));
    }
}

namespace detail {
    Bytes BlockBodyForStorage::encode() const {
        rlp::Header header{/*list=*/true, /*payload_length=*/0};
        header.payload_length += rlp::length(base_txn_id);
        header.payload_length += rlp::length(txn_count);
        header.payload_length += rlp::length(ommers);

        Bytes to;
        rlp::encode_header(to, header);
        rlp::encode(to, base_txn_id);
        rlp::encode(to, txn_count);
        rlp::encode(to, ommers);
        return to;
    }

    BlockBodyForStorage decode_stored_block_body(ByteView& from) {
        auto [header, err]{rlp::decode_header(from)};
        rlp::success_or_throw(err);
        if (!header.list) {
            rlp::success_or_throw(DecodingResult::kUnexpectedString);
        }
        uint64_t leftover{from.length() - header.payload_length};

        BlockBodyForStorage to;
        rlp::success_or_throw(rlp::decode(from, to.base_txn_id));
        rlp::success_or_throw(rlp::decode(from, to.txn_count));
        rlp::success_or_throw(rlp::decode_vector(from, to.ommers));

        if (from.length() != leftover) {
            throw rlp::DecodingError(DecodingResult::kListLengthMismatch);
        }

        return to;
    }

}  // namespace detail
}  // namespace silkworm::db
