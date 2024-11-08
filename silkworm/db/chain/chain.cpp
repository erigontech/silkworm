/*
   Copyright 2023 The Silkworm Authors

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

#include "chain.hpp"

#include <string>
#include <utility>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/rlp/decode.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::db::chain {

Task<uint64_t> read_header_number(kv::api::Transaction& tx, const evmc::bytes32& block_hash) {
    const ByteView block_hash_bytes{block_hash.bytes, kHashLength};
    const auto value{co_await tx.get_one(table::kHeaderNumbersName, block_hash_bytes)};
    if (value.empty()) {
        throw std::invalid_argument{"empty block number value in read_header_number"};
    }
    co_return endian::load_big_u64(value.data());
}

Task<std::optional<intx::uint256>> read_total_difficulty(kv::api::Transaction& tx, const evmc::bytes32& block_hash, uint64_t block_number) {
    const auto block_key = db::block_key(block_number, block_hash.bytes);
    SILK_TRACE << "read_total_difficulty block_key: " << to_hex(block_key);
    const auto result{co_await tx.get_one(table::kDifficultyName, block_key)};
    if (result.empty()) {
        co_return std::nullopt;
    }
    ByteView value{result};
    intx::uint256 total_difficulty{0};
    auto decoding_result{rlp::decode(value, total_difficulty)};
    if (!decoding_result) {
        throw std::runtime_error{"cannot RLP-decode total difficulty value in read_total_difficulty"};
    }
    SILK_DEBUG << "read_total_difficulty canonical total difficulty: " << total_difficulty;
    co_return total_difficulty;
}

Task<evmc::bytes32> read_head_header_hash(kv::api::Transaction& tx) {
    const Bytes kHeadHeaderKey = string_to_bytes(table::kHeadHeaderName);
    const auto value = co_await tx.get_one(table::kHeadHeaderName, kHeadHeaderKey);
    if (value.empty()) {
        throw std::runtime_error{"empty head header hash value in read_head_header_hash"};
    }
    const auto head_header_hash{to_bytes32(value)};
    SILK_DEBUG << "head header hash: " << to_hex(head_header_hash);
    co_return head_header_hash;
}

}  // namespace silkworm::db::chain
