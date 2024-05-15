/*
   Copyright 2024 The Silkworm Authors

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

#include "insertion.hpp"

#include <optional>

#include <catch2/catch.hpp>
#include <intx/intx.hpp>

#include <silkworm/interfaces/execution/execution.pb.h>
#include <silkworm/node/test_util/fixture.hpp>
#include <silkworm/node/test_util/sample_blocks.hpp>

#include "../../../test_util/sample_protos.hpp"

namespace silkworm::execution::grpc::server {

using namespace evmc::literals;
using namespace silkworm::execution::test_util;
using namespace silkworm::test_util;
namespace proto = ::execution;

static api::Blocks sample_blocks() {
    return {std::make_shared<Block>(), std::make_shared<Block>(sample_block())};
}

static void empty_proto_block(proto::Block* proto_block) {
    static const auto kEmptyHeaderHash{BlockHeader{}.hash()};
    proto_block->mutable_header()->set_allocated_block_hash(rpc::H256_from_bytes32(kEmptyHeaderHash).release());
    proto_block->mutable_body()->set_allocated_block_hash(rpc::H256_from_bytes32(kEmptyHeaderHash).release());
    ;
}

static proto::InsertBlocksRequest sample_proto_insert_block_request() {
    proto::InsertBlocksRequest request;
    empty_proto_block(request.add_blocks());  // first empty block
    sample_proto_block(request.add_blocks());
    return request;
}

static proto::InsertBlocksRequest sample_bad_proto_insert_block_request() {
    proto::InsertBlocksRequest request;
    proto::Block* proto_block = request.add_blocks();
    sample_proto_block(proto_block);
    // Block hash in both header and body set to wrong value (i.e. hash of empty string)
    proto_block->mutable_header()->set_allocated_block_hash(rpc::H256_from_bytes32(kEmptyHash).release());
    proto_block->mutable_body()->set_allocated_block_hash(rpc::H256_from_bytes32(kEmptyHash).release());
    return request;
}

TEST_CASE("blocks_from_insertion_request", "[node][execution][grpc]") {
    const Fixtures<proto::InsertBlocksRequest, std::optional<api::Blocks>> fixtures{
        {{}, api::Blocks{}},
        {sample_proto_insert_block_request(), sample_blocks()},
        {sample_bad_proto_insert_block_request(), std::nullopt},
    };
    for (const auto& [insertion_request, expected_blocks] : fixtures) {
        SECTION("blocks size: " + (expected_blocks ? std::to_string(expected_blocks->size()) : "null")) {
            const auto blocks{blocks_from_insertion_request(insertion_request)};
            REQUIRE(blocks.has_value() == expected_blocks.has_value());
            if (blocks) {
                REQUIRE(blocks->size() == expected_blocks->size());
                const size_t block_count{blocks->size()};
                for (size_t i{0}; i < block_count; ++i) {
                    const auto& block{blocks->at(i)};
                    const auto& expected_block{expected_blocks->at(i)};
                    REQUIRE((block && expected_block));
                    CHECK(*block == *expected_block);
                }
            }
        }
    }
}

}  // namespace silkworm::execution::grpc::server
