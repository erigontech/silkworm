// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "insertion.hpp"

#include <optional>

#include <catch2/catch_test_macros.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/test_util/sample_blocks.hpp>
#include <silkworm/infra/test_util/fixture.hpp>
#include <silkworm/interfaces/execution/execution.pb.h>

#include "../../test_util/sample_protos.hpp"

namespace silkworm::execution::grpc::client {

using namespace evmc::literals;
using namespace silkworm::execution::test_util;
using namespace silkworm::test_util;
namespace proto = ::execution;

static api::Blocks sample_blocks() {
    return {std::make_shared<Block>(), std::make_shared<Block>(sample_block())};
}

static void empty_proto_block(proto::Block* proto_block) {
    proto_block->mutable_header();
    proto_block->mutable_body();
}

static proto::InsertBlocksRequest sample_proto_insert_block_request() {
    proto::InsertBlocksRequest request;
    empty_proto_block(request.add_blocks());  // first empty block
    sample_proto_block(request.add_blocks());
    return request;
}

TEST_CASE("insertion_request_from_blocks", "[node][execution][grpc]") {
    const Fixtures<api::Blocks, proto::InsertBlocksRequest> fixtures{
        {{}, {}},
        {sample_blocks(), sample_proto_insert_block_request()},
    };
    for (const auto& [blocks, expected_insertion_request] : fixtures) {
        SECTION("blocks size: " + std::to_string(blocks.size())) {
            const auto insertion_request{insertion_request_from_blocks(blocks)};
            // CHECK(insertion_request == expected_insertion_request);  // requires operator== in gRPC generated code
            CHECK(insertion_request.blocks_size() == expected_insertion_request.blocks_size());
            if (insertion_request.blocks_size() == expected_insertion_request.blocks_size()) {
                for (int i{0}; i < insertion_request.blocks_size(); ++i) {
                    const auto& block{insertion_request.blocks(i)};
                    const auto& expected_block{expected_insertion_request.blocks(i)};
                    // CHECK(block == expected_block);  // requires operator== in gRPC generated code
                    CHECK(block.has_header() == expected_block.has_header());
                    if (block.has_header()) {
                        const auto& header{block.header()};
                        const auto& expected_header{expected_block.header()};
                        CHECK(header.block_number() == expected_header.block_number());
                    }
                    CHECK(block.has_body() == expected_block.has_body());
                }
            }
        }
    }
}

}  // namespace silkworm::execution::grpc::client
