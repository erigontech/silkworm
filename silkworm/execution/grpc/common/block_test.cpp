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

#include "block.hpp"

#include <string_view>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/test_util/sample_blocks.hpp>
#include <silkworm/infra/test_util/fixture.hpp>

#include "../test_util/sample_protos.hpp"

namespace silkworm::execution::grpc {

using namespace silkworm::execution::test_util;
using namespace silkworm::test_util;
namespace proto = ::execution;

TEST_CASE("deserialize_hex_as_bytes", "[node][execution][grpc]") {
    const Fixtures<std::string_view, std::vector<Bytes>> fixtures{
        {"", {Bytes{}}},
        {"0x01", {Bytes{0x01}}},
        {"0x0102", {Bytes{0x01, 0x02}}},
    };
    for (const auto& [hex, expected_byte_vector] : fixtures) {
        SECTION("hex bytes: " + std::to_string(expected_byte_vector.size())) {
            std::vector<Bytes> bb;
            CHECK_NOTHROW(deserialize_hex_as_bytes(hex, bb));
            CHECK(bb == expected_byte_vector);
        }
    }
    SECTION("invalid hex") {
        std::vector<Bytes> bb;
        CHECK_NOTHROW(deserialize_hex_as_bytes("00zz", bb));
        CHECK(bb.empty());
    }
}

TEST_CASE("header_from_proto", "[node][execution][grpc]") {
    const Fixtures<proto::Header, BlockHeader> fixtures{
        {{}, {}},
        {sample_proto_header(), sample_block_header()},
    };
    for (const auto& [proto_header, expected_block_header] : fixtures) {
        SECTION("header: " + std::to_string(proto_header.block_num())) {
            BlockHeader header;
            CHECK_NOTHROW(header_from_proto(proto_header, header));
            CHECK(header == expected_block_header);
            CHECK(header_from_proto(proto_header) == expected_block_header);
        }
    }
}

TEST_CASE("convertibility", "[node][execution][grpc]") {
    const Fixtures<proto::Header, BlockHeader> fixtures{
        {{}, {}},
        {sample_proto_header(), sample_block_header()},
    };
    for (const auto& [expected_proto_header, expected_block_header] : fixtures) {
        SECTION("header: " + std::to_string(expected_proto_header.block_num())) {
            const BlockHeader header = header_from_proto(expected_proto_header);
            CHECK(header == expected_block_header);
            proto::Header proto_header;
            proto_from_header(header, &proto_header);
            // CHECK(proto_header == expected_proto_header);  // requires operator== for proto::Header
            CHECK(header_from_proto(proto_header) == expected_block_header);
        }
    }
}

}  // namespace silkworm::execution::grpc
