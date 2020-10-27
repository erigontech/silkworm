/*
   Copyright 2020 The Silkworm Authors

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

#include <boost/endian/conversion.hpp>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <intx/int128.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/rlp/encode.hpp>

namespace silkworm::db {

Bytes storage_prefix(const evmc::address& address, uint64_t incarnation) {
    Bytes res(kStoragePrefixLength, '\0');
    std::memcpy(&res[0], address.bytes, kAddressLength);
    boost::endian::store_big_u64(&res[kAddressLength], incarnation);
    return res;
}

Bytes storage_key(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& key) {
    Bytes res(kStoragePrefixLength + kHashLength, '\0');
    std::memcpy(&res[0], address.bytes, kAddressLength);
    boost::endian::store_big_u64(&res[kAddressLength], incarnation);
    std::memcpy(&res[kStoragePrefixLength], key.bytes, kHashLength);
    return res;
}

Bytes header_hash_key(uint64_t block_number) {
    Bytes key(8 + 1, '\0');
    boost::endian::store_big_u64(&key[0], block_number);
    key[8] = 'n';
    return key;
}

Bytes block_key(uint64_t block_number, const uint8_t (&hash)[kHashLength]) {
    Bytes key(8 + kHashLength, '\0');
    boost::endian::store_big_u64(&key[0], block_number);
    std::memcpy(&key[8], hash, kHashLength);
    return key;
}

Bytes history_index_key(ByteView key, uint64_t block_number) {
    Bytes res{};
    if (key.length() == kAddressLength) {  // accounts
        res = key;
        res.resize(kAddressLength + 8);
        boost::endian::store_big_u64(&res[kAddressLength], block_number);
    } else if (key.length() == kStoragePrefixLength + kHashLength) {  // storage
        // remove incarnation and add block number
        res.resize(kStoragePrefixLength + kHashLength);
        std::memcpy(&res[0], &key[0], kAddressLength);
        std::memcpy(&res[kAddressLength], &key[kStoragePrefixLength], kHashLength);
        boost::endian::store_big_u64(&res[kAddressLength + kHashLength], block_number);
    } else {
        throw std::invalid_argument{"unexpected key length"};
    }
    return res;
}

Bytes encode_timestamp(uint64_t block_number) {
    static constexpr size_t kByteCountBits{3};
    size_t zero_bits{intx::clz(block_number)};
    assert(zero_bits >= kByteCountBits);
    size_t byte_count{8 - (zero_bits - kByteCountBits) / 8};
    Bytes encoded(byte_count, '\0');
    ByteView be{rlp::big_endian(block_number)};
    std::memcpy(&encoded[byte_count - be.length()], &be[0], be.length());
    encoded[0] |= byte_count << (8 - kByteCountBits);
    return encoded;
}

Bytes receipt_key(uint64_t block_number) {
    Bytes key(8, '\0');
    boost::endian::store_big_u64(&key[0], block_number);
    return key;
}

Bytes log_key(uint64_t block_number, uint32_t transaction_id) {
    Bytes key(8 + 4, '\0');
    boost::endian::store_big_u64(&key[0], block_number);
    boost::endian::store_big_u32(&key[8], transaction_id);
    return key;
}

// See Turbo-Geth DefaultDataDir
std::string default_path() {
    std::string base_dir{};

    const char* env{std::getenv("XDG_DATA_HOME")};
    if (env) {
        base_dir = env;
    } else {
        env = std::getenv("APPDATA");
        if (env) {
            base_dir = env;
        }
    }

    if (base_dir.empty()) {
#if defined(_WIN32)
        /* Should not happen */
        return base_dir;
#else
        env = std::getenv("HOME");
        if (!env) {
            return base_dir;
        }
#endif
        std::string home_dir{env};

#ifdef _WIN32
        base_dir = home_dir;
#elif __APPLE__
        base_dir = home_dir + "/Library";
#else
        base_dir = home_dir + "/.local/share";
#endif
    }

#if defined(_WIN32) || defined(__APPLE__)
    base_dir += "/TurboGeth";
#else
    base_dir += "/turbogeth";
#endif

    return base_dir + "/tg/chaindata";
}
}  // namespace silkworm::db
