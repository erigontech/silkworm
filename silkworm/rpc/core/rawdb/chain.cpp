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
static Task<silkworm::Bytes> read_body_rlp(ethdb::Transaction& tx, const evmc::bytes32& block_hash, BlockNum block_number);

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

Task<uint64_t> read_cumulative_transaction_count(ethdb::Transaction& tx, uint64_t block_number) {
    const auto block_hash = co_await read_canonical_block_hash(tx, block_number);
    const auto data = co_await read_body_rlp(tx, block_hash, block_number);
    if (data.empty()) {
        throw std::runtime_error{"empty block body RLP in read_body"};
    }
    SILK_TRACE << "RLP data for block body #" << block_number << ": " << silkworm::to_hex(data);

    try {
        silkworm::ByteView data_view{data};
        auto stored_body{silkworm::unwrap_or_throw(silkworm::decode_stored_block_body(data_view))};
        // 1 system txn in the beginning of block, and 1 at the end
        SILK_DEBUG << "base_txn_id: " << stored_body.base_txn_id + 1 << " txn_count: " << stored_body.txn_count - 2;
        co_return stored_body.base_txn_id + stored_body.txn_count - 1;
    } catch (const silkworm::DecodingException& error) {
        SILK_ERROR << "RLP decoding error for block body #" << block_number << " [" << error.what() << "]";
        throw std::runtime_error{"RLP decoding error for block body [" + std::string(error.what()) + "]"};
    }
}

Task<silkworm::Bytes> read_body_rlp(ethdb::Transaction& tx, const evmc::bytes32& block_hash, BlockNum block_number) {
    const auto block_key = silkworm::db::block_key(block_number, block_hash.bytes);
    co_return co_await tx.get_one(db::table::kBlockBodiesName, block_key);
}

Task<intx::uint256> read_total_issued(ethdb::Transaction& tx, BlockNum block_number) {
    const auto block_key = silkworm::db::block_key(block_number);
    const auto value = co_await tx.get_one(db::table::kIssuanceName, block_key);
    intx::uint256 total_issued = 0;
    if (!value.empty()) {
        total_issued = std::stoul(silkworm::to_hex(value), nullptr, 16);
    }
    SILK_DEBUG << "rawdb::read_total_issued: " << total_issued;
    co_return total_issued;
}

Task<intx::uint256> read_total_burnt(ethdb::Transaction& tx, BlockNum block_number) {
    const auto block_key = silkworm::db::block_key(block_number);
    const std::string kBurnt{"burnt"};
    silkworm::Bytes key{kBurnt.begin(), kBurnt.end()};
    key.append(block_key.begin(), block_key.end());
    const auto value = co_await tx.get_one(db::table::kIssuanceName, key);
    intx::uint256 total_burnt = 0;
    if (!value.empty()) {
        total_burnt = std::stoul(silkworm::to_hex(value), nullptr, 16);
    }
    SILK_DEBUG << "rawdb::read_total_burnt: " << total_burnt;
    co_return total_burnt;
}

Task<intx::uint256> read_cumulative_gas_used(ethdb::Transaction& tx, BlockNum block_number) {
    const auto block_key = silkworm::db::block_key(block_number);
    const auto value = co_await tx.get_one(db::table::kCumulativeGasIndexName, block_key);
    intx::uint256 cumulative_gas_index = 0;
    if (!value.empty()) {
        cumulative_gas_index = std::stoul(silkworm::to_hex(value), nullptr, 16);
    }
    SILK_DEBUG << "rawdb::read_cumulative_gas_used: " << cumulative_gas_index;
    co_return cumulative_gas_index;
}

}  // namespace silkworm::rpc::core::rawdb
