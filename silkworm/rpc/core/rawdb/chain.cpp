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

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/rlp/decode.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/block_body_for_storage.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/core/blocks.hpp>

namespace silkworm::rpc::core::rawdb {

/* Local Routines */
Task<uint64_t> read_header_number(ethdb::Transaction& tx, const evmc::bytes32& block_hash) {
    const silkworm::ByteView block_hash_bytes{block_hash.bytes, silkworm::kHashLength};
    const auto value{co_await tx.get_one(db::table::kHeaderNumbersName, block_hash_bytes)};
    if (value.empty()) {
        throw std::invalid_argument{"empty block number value in read_header_number"};
    }
    co_return endian::load_big_u64(value.data());
}

Task<evmc::bytes32> read_canonical_block_hash(ethdb::Transaction& tx, uint64_t block_number) {
    const auto block_key = silkworm::db::block_key(block_number);
    SILK_TRACE << "rawdb::read_canonical_block_hash block_key: " << silkworm::to_hex(block_key);
    const auto value{co_await tx.get_one(db::table::kCanonicalHashesName, block_key)};
    if (value.empty()) {
        throw std::invalid_argument{"empty block hash value in read_canonical_block_hash"};
    }
    const auto canonical_block_hash{silkworm::to_bytes32(value)};
    SILK_DEBUG << "rawdb::read_canonical_block_hash canonical block hash: " << silkworm::to_hex(canonical_block_hash);
    co_return canonical_block_hash;
}

Task<intx::uint256> read_total_difficulty(ethdb::Transaction& tx, const evmc::bytes32& block_hash, uint64_t block_number) {
    const auto block_key = silkworm::db::block_key(block_number, block_hash.bytes);
    SILK_TRACE << "rawdb::read_total_difficulty block_key: " << silkworm::to_hex(block_key);
    const auto result{co_await tx.get_one(db::table::kDifficultyName, block_key)};
    if (result.empty()) {
        throw std::invalid_argument{"empty total difficulty value in read_total_difficulty"};
    }
    silkworm::ByteView value{result};
    intx::uint256 total_difficulty{0};
    auto decoding_result{silkworm::rlp::decode(value, total_difficulty)};
    if (!decoding_result) {
        throw std::runtime_error{"cannot RLP-decode total difficulty value in read_total_difficulty"};
    }
    SILK_DEBUG << "rawdb::read_total_difficulty canonical total difficulty: " << total_difficulty;
    co_return total_difficulty;
}

Task<evmc::bytes32> read_head_header_hash(ethdb::Transaction& tx) {
    const silkworm::Bytes kHeadHeaderKey = silkworm::bytes_of_string(db::table::kHeadHeaderName);
    const auto value = co_await tx.get_one(db::table::kHeadHeaderName, kHeadHeaderKey);
    if (value.empty()) {
        throw std::invalid_argument{"empty head header hash value in read_head_header_hash"};
    }
    const auto head_header_hash{silkworm::to_bytes32(value)};
    SILK_DEBUG << "head header hash: " << silkworm::to_hex(head_header_hash);
    co_return head_header_hash;
}

}  // namespace silkworm::rpc::core::rawdb
