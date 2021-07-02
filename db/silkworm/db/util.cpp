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

#include <silkworm/common/util.hpp>
#include <silkworm/rlp/decode.hpp>
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
    auto data{table.lower_bound_multivalue(to_slice(key), to_slice(value_prefix), /*throw_notfound*/ false)};
    if (!data) {
        return std::nullopt;
    }
    ByteView value{from_slice(data.value)};
    if (!has_prefix(value, value_prefix)) {
        return std::nullopt;
    } else {
        value.remove_prefix(value_prefix.length());
        return value;
    }
}

// See Erigon DefaultDataDir
std::string default_path() {
    std::string base_dir{};

    const char* env{std::getenv("XDG_DATA_HOME")};
    if (env) {
        base_dir = env;
    } else {
#ifdef _WIN32
        std::string env_name{"APPDATA"};
#else
        std::string env_name{"HOME"};
#endif
        env = std::getenv(env_name.c_str());
        if (env) {
            base_dir = env;
        } else {
            return base_dir;  // We actually don't know where to persist data
        };
    }

#ifdef _WIN32
    base_dir += "/Erigon";
#elif __APPLE__
    base_dir += "/Library/Erigon";
#else
    base_dir += "/.local/share/erigon";
#endif

    return base_dir + "/erigon/chaindata";
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

    static void check_rlp_err(rlp::DecodingResult err) {
        if (err != rlp::DecodingResult::kOk) {
            throw err;
        }
    }

    BlockBodyForStorage decode_stored_block_body(ByteView& from) {
        auto [header, err]{rlp::decode_header(from)};
        check_rlp_err(err);
        if (!header.list) {
            throw rlp::DecodingResult::kUnexpectedString;
        }
        uint64_t leftover{from.length() - header.payload_length};

        BlockBodyForStorage to;
        check_rlp_err(rlp::decode(from, to.base_txn_id));
        check_rlp_err(rlp::decode(from, to.txn_count));
        check_rlp_err(rlp::decode_vector(from, to.ommers));

        if (from.length() != leftover) {
            throw rlp::DecodingResult::kListLengthMismatch;
        }

        return to;
    }

}  // namespace detail
}  // namespace silkworm::db
