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

#include "util.hpp"

#include <cassert>
#include <cstdlib>
#include <cstring>

#include <boost/endian/conversion.hpp>
#include <intx/int128.hpp>

#include <silkworm/common/rlp_err.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/rlp/encode.hpp>

namespace silkworm::db {

Bytes storage_prefix(ByteView address, uint64_t incarnation) {
    Bytes res(address.length() + kIncarnationLength, '\0');
    std::memcpy(&res[0], address.data(), address.length());
    boost::endian::store_big_u64(&res[address.length()], incarnation);
    return res;
}

Bytes block_key(uint64_t block_number) {
    Bytes key(8, '\0');
    boost::endian::store_big_u64(&key[0], block_number);
    return key;
}

Bytes block_key(uint64_t block_number, const uint8_t (&hash)[kHashLength]) {
    Bytes key(8 + kHashLength, '\0');
    boost::endian::store_big_u64(&key[0], block_number);
    std::memcpy(&key[8], hash, kHashLength);
    return key;
}

Bytes storage_change_key(uint64_t block_number, const evmc::address& address, uint64_t incarnation) {
    Bytes res(8 + kStoragePrefixLength, '\0');
    boost::endian::store_big_u64(&res[0], block_number);
    std::memcpy(&res[8], address.bytes, kAddressLength);
    boost::endian::store_big_u64(&res[8 + kAddressLength], incarnation);
    return res;
}

Bytes account_history_key(const evmc::address& address, uint64_t block_number) {
    Bytes res(kAddressLength + 8, '\0');
    std::memcpy(&res[0], address.bytes, kAddressLength);
    boost::endian::store_big_u64(&res[kAddressLength], block_number);
    return res;
}

Bytes storage_history_key(const evmc::address& address, const evmc::bytes32& location, uint64_t block_number) {
    Bytes res(kAddressLength + kHashLength + 8, '\0');
    std::memcpy(&res[0], address.bytes, kAddressLength);
    std::memcpy(&res[kAddressLength], location.bytes, kHashLength);
    boost::endian::store_big_u64(&res[kAddressLength + kHashLength], block_number);
    return res;
}

Bytes log_key(uint64_t block_number, uint32_t transaction_id) {
    Bytes key(8 + 4, '\0');
    boost::endian::store_big_u64(&key[0], block_number);
    boost::endian::store_big_u32(&key[8], transaction_id);
    return key;
}

std::optional<ByteView> find_value_suffix(mdbx::cursor& table, ByteView key, ByteView value_prefix) {
    auto prefix_slice{to_slice(value_prefix)};
    auto data{table.lower_bound_multivalue(to_slice(key), prefix_slice, /*throw_notfound*/ false)};
    if (!data || !data.value.starts_with(prefix_slice)) {
        return std::nullopt;
    }

    ByteView res{from_slice(data.value)};
    res.remove_prefix(value_prefix.length());
    return res;
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
        rlp::err_handler(err);
        if (!header.list) {
            rlp::err_handler(rlp::DecodingResult::kUnexpectedString);
        }
        uint64_t leftover{from.length() - header.payload_length};

        BlockBodyForStorage to;
        rlp::err_handler(rlp::decode(from, to.base_txn_id));
        rlp::err_handler(rlp::decode(from, to.txn_count));
        rlp::err_handler(rlp::decode_vector(from, to.ommers));

        if (from.length() != leftover) {
            throw rlp::DecodingResult::kListLengthMismatch;
        }

        return to;
    }

}  // namespace detail
}  // namespace silkworm::db
