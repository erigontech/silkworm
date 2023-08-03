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

Bytes storage_prefix(ByteView address, uint64_t incarnation) {
    SILKWORM_ASSERT(address.length() == kAddressLength || address.length() == kHashLength);
    Bytes res(address.length() + kIncarnationLength, '\0');
    std::memcpy(&res[0], address.data(), address.length());
    endian::store_big_u64(&res[address.length()], incarnation);
    return res;
}

Bytes block_key(BlockNum block_number) {
    Bytes key(sizeof(BlockNum), '\0');
    endian::store_big_u64(&key[0], block_number);
    return key;
}

Bytes block_key(BlockNum block_number, std::span<const uint8_t, kHashLength> hash) {
    Bytes key(sizeof(BlockNum) + kHashLength, '\0');
    endian::store_big_u64(&key[0], block_number);
    std::memcpy(&key[8], hash.data(), kHashLength);
    return key;
}

auto split_block_key(ByteView key) -> std::tuple<BlockNum, evmc::bytes32> {
    SILKWORM_ASSERT(key.size() == sizeof(BlockNum) + kHashLength);

    ByteView block_num_part = key.substr(0, sizeof(BlockNum));
    BlockNum block_num = endian::load_big_u64(block_num_part.data());

    ByteView hash_part = key.substr(sizeof(BlockNum));
    evmc::bytes32 hash;
    std::memcpy(hash.bytes, hash_part.data(), hash_part.length());

    return {block_num, hash};
}

Bytes storage_change_key(BlockNum block_number, const evmc::address& address, uint64_t incarnation) {
    Bytes res(sizeof(BlockNum) + kPlainStoragePrefixLength, '\0');
    endian::store_big_u64(&res[0], block_number);
    std::memcpy(&res[8], address.bytes, kAddressLength);
    endian::store_big_u64(&res[8 + kAddressLength], incarnation);
    return res;
}

Bytes account_history_key(const evmc::address& address, BlockNum block_number) {
    Bytes res(kAddressLength + sizeof(BlockNum), '\0');
    std::memcpy(&res[0], address.bytes, kAddressLength);
    endian::store_big_u64(&res[kAddressLength], block_number);
    return res;
}

Bytes storage_history_key(const evmc::address& address, const evmc::bytes32& location, BlockNum block_number) {
    Bytes res(kAddressLength + kHashLength + sizeof(BlockNum), '\0');
    std::memcpy(&res[0], address.bytes, kAddressLength);
    std::memcpy(&res[kAddressLength], location.bytes, kHashLength);
    endian::store_big_u64(&res[kAddressLength + kHashLength], block_number);
    return res;
}

Bytes log_key(BlockNum block_number, uint32_t transaction_id) {
    Bytes key(sizeof(BlockNum) + sizeof(uint32_t), '\0');
    endian::store_big_u64(&key[0], block_number);
    endian::store_big_u32(&key[8], transaction_id);
    return key;
}

BlockNum block_number_from_key(const mdbx::slice& key) {
    SILKWORM_ASSERT(key.size() >= sizeof(BlockNum));
    ByteView key_view{from_slice(key)};
    return endian::load_big_u64(key_view.data());
}

std::pair<Bytes, Bytes> changeset_to_plainstate_format(const ByteView key, ByteView value) {
    if (key.size() == sizeof(BlockNum)) {
        if (value.length() < kAddressLength) {
            throw std::runtime_error("Invalid value length " + std::to_string(value.length()) +
                                     " for account changeset in " + std::string(__FUNCTION__));
        }
        // AccountChangeSet
        const Bytes address{value.substr(0, kAddressLength)};
        const Bytes previous_value{value.substr(kAddressLength)};
        return {address, previous_value};
    } else if (key.length() == sizeof(BlockNum) + kPlainStoragePrefixLength) {
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

std::optional<ByteView> find_value_suffix(ROCursorDupSort& table, ByteView key, ByteView value_prefix) {
    auto value_prefix_slice{to_slice(value_prefix)};
    auto data{table.lower_bound_multivalue(to_slice(key), value_prefix_slice, /*throw_notfound=*/false)};
    if (!data || !data.value.starts_with(value_prefix_slice)) {
        return std::nullopt;
    }

    ByteView res{from_slice(data.value)};
    res.remove_prefix(value_prefix.length());
    return res;
}

void upsert_storage_value(RWCursorDupSort& state_cursor, ByteView storage_prefix, ByteView location, ByteView new_value) {
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
        rlp::Header header{.list = true, .payload_length = 0};
        header.payload_length += rlp::length(base_txn_id);
        header.payload_length += rlp::length(txn_count);
        header.payload_length += rlp::length(ommers);
        if (withdrawals) {
            header.payload_length += rlp::length(*withdrawals);
        }

        Bytes to;
        rlp::encode_header(to, header);
        rlp::encode(to, base_txn_id);
        rlp::encode(to, txn_count);
        rlp::encode(to, ommers);
        if (withdrawals) {
            rlp::encode(to, *withdrawals);
        }

        return to;
    }

    DecodingResult decode_stored_block_body(ByteView& from, BlockBodyForStorage& to) {
        const auto header{rlp::decode_header(from)};
        if (!header) {
            return tl::unexpected{header.error()};
        }
        if (!header->list) {
            return tl::unexpected{DecodingError::kUnexpectedString};
        }
        const uint64_t leftover{from.length() - header->payload_length};
        if (leftover) {
            return tl::unexpected{DecodingError::kInputTooLong};
        }

        if (DecodingResult res{rlp::decode_items(from, to.base_txn_id, to.txn_count, to.ommers)}; !res) {
            return res;
        }

        to.withdrawals = std::nullopt;
        if (from.length() > leftover) {
            std::vector<Withdrawal> withdrawals;
            if (DecodingResult res{rlp::decode(from, withdrawals, rlp::Leftover::kAllow)}; !res) {
                return res;
            }
            to.withdrawals = withdrawals;
        }

        if (from.length() != leftover) {
            return tl::unexpected{DecodingError::kUnexpectedListElements};
        }
        return {};
    }

    BlockBodyForStorage decode_stored_block_body(ByteView& from) {
        BlockBodyForStorage to;
        success_or_throw(decode_stored_block_body(from, to));
        return to;
    }

}  // namespace detail
}  // namespace silkworm::db
