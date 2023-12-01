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

#include "block.hpp"

#include <sstream>

#include <catch2/catch.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc {

using Catch::Matchers::Message;
using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

evmc::bytes32 kZeroHash{0};

TEST_CASE("block_number_or_hash") {
    SECTION("ctor from hash string") {
        BlockNumberOrHash bnoh{"0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c"};

        CHECK(bnoh.is_hash() == true);
        CHECK(bnoh.is_number() == false);
        CHECK(bnoh.is_tag() == false);

        CHECK(bnoh.hash() == 0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32);
        CHECK(bnoh.number() == 0);
        CHECK(bnoh.tag().empty());
    }
    SECTION("ctor from decimal number string") {
        BlockNumberOrHash bnoh{"1966"};

        CHECK(bnoh.is_hash() == false);
        CHECK(bnoh.is_number() == true);
        CHECK(bnoh.is_tag() == false);

        CHECK(bnoh.hash() == kZeroHash);
        CHECK(bnoh.number() == 1966);
        CHECK(bnoh.tag().empty());
    }
    SECTION("ctor from hex number string") {
        BlockNumberOrHash bnoh{"0x374f3"};

        CHECK(bnoh.is_hash() == false);
        CHECK(bnoh.is_number() == true);
        CHECK(bnoh.is_tag() == false);

        CHECK(bnoh.hash() == kZeroHash);
        CHECK(bnoh.number() == 0x374f3);
        CHECK(bnoh.tag().empty());
    }
    SECTION("ctor from 'latest' tag") {
        BlockNumberOrHash bnoh{"latest"};

        CHECK(bnoh.is_hash() == false);
        CHECK(bnoh.is_number() == false);
        CHECK(bnoh.is_tag() == true);

        CHECK(bnoh.hash() == kZeroHash);
        CHECK(bnoh.number() == 0);
        CHECK(bnoh.tag() == "latest");
    }
    SECTION("ctor from 'earliest' tag") {
        BlockNumberOrHash bnoh{"earliest"};

        CHECK(bnoh.is_hash() == false);
        CHECK(bnoh.is_number() == true);
        CHECK(bnoh.is_tag() == false);

        CHECK(bnoh.hash() == kZeroHash);
        CHECK(bnoh.number() == 0);
        CHECK(bnoh.tag().empty());
    }
    SECTION("ctor from 'pending' tag") {
        BlockNumberOrHash bnoh{"pending"};

        CHECK(bnoh.is_hash() == false);
        CHECK(bnoh.is_number() == false);
        CHECK(bnoh.is_tag() == true);

        CHECK(bnoh.hash() == kZeroHash);
        CHECK(bnoh.number() == 0);
        CHECK(bnoh.tag() == "pending");
    }
    SECTION("ctor from number") {
        BlockNumberOrHash bnoh{123456};

        CHECK(bnoh.is_hash() == false);
        CHECK(bnoh.is_number() == true);
        CHECK(bnoh.is_tag() == false);

        CHECK(bnoh.hash() == kZeroHash);
        CHECK(bnoh.number() == 123456);
        CHECK(bnoh.tag().empty());
    }
    SECTION("copy ctor") {
        BlockNumberOrHash bnoh{"0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c"};
        BlockNumberOrHash copy{bnoh};

        CHECK(bnoh.is_hash() == copy.is_hash());
        CHECK(bnoh.is_number() == copy.is_number());
        CHECK(bnoh.is_tag() == copy.is_tag());

        CHECK(bnoh.hash() == copy.hash());
        CHECK(bnoh.number() == 0);
        CHECK(bnoh.tag().empty());
    }
    SECTION("copy hash") {
        BlockNumberOrHash bnoh{"0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c"};
        BlockNumberOrHash copy = bnoh;

        CHECK(bnoh.is_hash() == copy.is_hash());
        CHECK(bnoh.is_number() == copy.is_number());
        CHECK(bnoh.is_tag() == copy.is_tag());

        CHECK(bnoh.hash() == copy.hash());
    }
    SECTION("copy number") {
        BlockNumberOrHash bnoh{123456};
        BlockNumberOrHash copy = bnoh;

        CHECK(bnoh.is_hash() == copy.is_hash());
        CHECK(bnoh.is_number() == copy.is_number());
        CHECK(bnoh.is_tag() == copy.is_tag());

        CHECK(bnoh.number() == copy.number());
    }
    SECTION("copy tag") {
        BlockNumberOrHash bnoh{"latest"};
        BlockNumberOrHash copy = bnoh;

        CHECK(bnoh.is_hash() == copy.is_hash());
        CHECK(bnoh.is_number() == copy.is_number());
        CHECK(bnoh.is_tag() == copy.is_tag());
        CHECK(bnoh.tag() == copy.tag());
    }
    SECTION("number overflow") {
        CHECK_THROWS_AS(BlockNumberOrHash{"0x1ffffffffffffffff"}, std::out_of_range);
    }
    SECTION("invalid string") {
        CHECK_THROWS_AS(BlockNumberOrHash{"invalid"}, std::invalid_argument);
    }
    SECTION("operator<<") {
        std::stringstream out;

        BlockNumberOrHash bnoh1{"0x374f3"};
        out << bnoh1;
        CHECK(out.str() == "0x374f3");
        out.str("");

        BlockNumberOrHash bnoh2{"0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c"};
        out << bnoh2;
        CHECK(out.str() == "0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c");
        out.str("");

        BlockNumberOrHash bnoh3{"latest"};
        out << bnoh3;
        CHECK(out.str() == "latest");
        out.str("");

        BlockNumberOrHash bnoh4{"pending"};
        out << bnoh4;
        CHECK(out.str() == "pending");
        out.str("");
    }
}

TEST_CASE("create empty block", "[silkrpc][types][block]") {
    Block b{};
    CHECK(b.total_difficulty == 0);
    CHECK(b.full_tx == false);
}

TEST_CASE("check size of EIP-2718 block from RLP", "[silkrpc][types][block]") {
    const char* rlp_hex{
        "f90319f90211a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd4"
        "1ad312451b948a7413f0a142fd40d49347948888f1f195afa192cfee860698584c030f4c9db1a0ef1552a40b7165c3cd773806b9e0c165"
        "b75356e0314bf0706f279c729f51e017a0e6e49996c7ec59f7a23d22b83239a60151512c65613bf84a0d7da336399ebc4aa0cafe75574d"
        "59780665a97fbfd11365c7545aa8f1abf4e5e12e8243334ef7286bb9010000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000083020000820200832fefd882a410845506eb0796636f6f6c65737420626c6f636b206f6e20636861696ea0bd"
        "4472abb6659ebe3ee06ee4d7b72a00a9f4d001caca51342001075469aff49888a13a5a8c8f2bb1c4f90101f85f800a82c35094095e7bae"
        "a6a6c7c4c2dfeb977efac326af552d870a801ba09bea4c4daac7c7c52e093e6a4c35dbbcf8856f1af7b059ba20253e70848d094fa08a8f"
        "ae537ce25ed8cb5af9adac3f141af69bd515bd2ba031522df09b97dd72b1b89e01f89b01800a8301e24194095e7baea6a6c7c4c2dfeb97"
        "7efac326af552d878080f838f7940000000000000000000000000000000000000001e1a000000000000000000000000000000000000000"
        "0000000000000000000000000001a03dbacc8d0259f2508625e97fdfc57cd85fdd16e5821bc2c10bdd1a52649e8335a0476e10695b183a"
        "87b0aa292a7f4b78ef0c3fbe62aa2c42c84e1d9c3da159ef14c0"};

    silkworm::Bytes rlp_bytes{*silkworm::from_hex(rlp_hex)};
    silkworm::ByteView view{rlp_bytes};
    auto block_with_hash = std::make_shared<BlockWithHash>();

    Block rpc_block{block_with_hash};

    REQUIRE(silkworm::rlp::decode(view, rpc_block.block_with_hash->block));
    CHECK(view.empty());

    CHECK(rpc_block.get_block_size() == rlp_bytes.size());
    CHECK_NOTHROW(test_util::null_stream() << rpc_block);
}

}  // namespace silkworm::rpc
