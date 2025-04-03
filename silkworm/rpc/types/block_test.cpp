// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "block.hpp"

#include <sstream>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/test_util/null_stream.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc {

using evmc::literals::operator""_bytes32;

evmc::bytes32 kZeroHash{0};

TEST_CASE("block_num_or_hash") {
    SECTION("ctor from hash string") {
        BlockNumOrHash block_num_or_hash{"0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c"};

        CHECK(block_num_or_hash.is_hash() == true);
        CHECK(block_num_or_hash.is_number() == false);
        CHECK(block_num_or_hash.is_tag() == false);

        CHECK(block_num_or_hash.hash() == 0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32);
        CHECK(block_num_or_hash.number() == 0);
        CHECK(block_num_or_hash.tag().empty());
    }
    SECTION("ctor from decimal number string") {
        BlockNumOrHash block_num_or_hash{"1966"};

        CHECK(block_num_or_hash.is_hash() == false);
        CHECK(block_num_or_hash.is_number() == true);
        CHECK(block_num_or_hash.is_tag() == false);

        CHECK(block_num_or_hash.hash() == kZeroHash);
        CHECK(block_num_or_hash.number() == 1966);
        CHECK(block_num_or_hash.tag().empty());
    }
    SECTION("ctor from hex number string") {
        BlockNumOrHash block_num_or_hash{"0x374f3"};

        CHECK(block_num_or_hash.is_hash() == false);
        CHECK(block_num_or_hash.is_number() == true);
        CHECK(block_num_or_hash.is_tag() == false);

        CHECK(block_num_or_hash.hash() == kZeroHash);
        CHECK(block_num_or_hash.number() == 0x374f3);
        CHECK(block_num_or_hash.tag().empty());
    }
    SECTION("ctor from 'latest' tag") {
        BlockNumOrHash block_num_or_hash{"latest"};

        CHECK(block_num_or_hash.is_hash() == false);
        CHECK(block_num_or_hash.is_number() == false);
        CHECK(block_num_or_hash.is_tag() == true);

        CHECK(block_num_or_hash.hash() == kZeroHash);
        CHECK(block_num_or_hash.number() == 0);
        CHECK(block_num_or_hash.tag() == "latest");
    }
    SECTION("ctor from 'earliest' tag") {
        BlockNumOrHash block_num_or_hash{"earliest"};

        CHECK(block_num_or_hash.is_hash() == false);
        CHECK(block_num_or_hash.is_number() == true);
        CHECK(block_num_or_hash.is_tag() == false);

        CHECK(block_num_or_hash.hash() == kZeroHash);
        CHECK(block_num_or_hash.number() == 0);
        CHECK(block_num_or_hash.tag().empty());
    }
    SECTION("ctor from 'pending' tag") {
        BlockNumOrHash block_num_or_hash{"pending"};

        CHECK(block_num_or_hash.is_hash() == false);
        CHECK(block_num_or_hash.is_number() == false);
        CHECK(block_num_or_hash.is_tag() == true);

        CHECK(block_num_or_hash.hash() == kZeroHash);
        CHECK(block_num_or_hash.number() == 0);
        CHECK(block_num_or_hash.tag() == "pending");
    }
    SECTION("ctor from number") {
        BlockNumOrHash block_num_or_hash{123456};

        CHECK(block_num_or_hash.is_hash() == false);
        CHECK(block_num_or_hash.is_number() == true);
        CHECK(block_num_or_hash.is_tag() == false);

        CHECK(block_num_or_hash.hash() == kZeroHash);
        CHECK(block_num_or_hash.number() == 123456);
        CHECK(block_num_or_hash.tag().empty());
    }
    SECTION("copy ctor") {
        BlockNumOrHash block_num_or_hash{"0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c"};
        BlockNumOrHash copy{block_num_or_hash};  // NOLINT(performance-unnecessary-copy-initialization)

        CHECK(block_num_or_hash.is_hash() == copy.is_hash());
        CHECK(block_num_or_hash.is_number() == copy.is_number());
        CHECK(block_num_or_hash.is_tag() == copy.is_tag());

        CHECK(block_num_or_hash.hash() == copy.hash());
        CHECK(block_num_or_hash.number() == 0);
        CHECK(block_num_or_hash.tag().empty());
    }
    SECTION("copy hash") {
        BlockNumOrHash block_num_or_hash{"0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c"};
        BlockNumOrHash copy = block_num_or_hash;  // NOLINT(performance-unnecessary-copy-initialization)

        CHECK(block_num_or_hash.is_hash() == copy.is_hash());
        CHECK(block_num_or_hash.is_number() == copy.is_number());
        CHECK(block_num_or_hash.is_tag() == copy.is_tag());

        CHECK(block_num_or_hash.hash() == copy.hash());
    }
    SECTION("copy number") {
        BlockNumOrHash block_num_or_hash{123456};
        BlockNumOrHash copy = block_num_or_hash;  // NOLINT(performance-unnecessary-copy-initialization)

        CHECK(block_num_or_hash.is_hash() == copy.is_hash());
        CHECK(block_num_or_hash.is_number() == copy.is_number());
        CHECK(block_num_or_hash.is_tag() == copy.is_tag());

        CHECK(block_num_or_hash.number() == copy.number());
    }
    SECTION("copy tag") {
        BlockNumOrHash block_num_or_hash{"latest"};
        BlockNumOrHash copy = block_num_or_hash;  // NOLINT(performance-unnecessary-copy-initialization)

        CHECK(block_num_or_hash.is_hash() == copy.is_hash());
        CHECK(block_num_or_hash.is_number() == copy.is_number());
        CHECK(block_num_or_hash.is_tag() == copy.is_tag());
        CHECK(block_num_or_hash.tag() == copy.tag());
    }
    SECTION("number overflow") {
        CHECK_THROWS_AS(BlockNumOrHash{"0x1ffffffffffffffff"}, std::out_of_range);
    }
    SECTION("invalid string") {
        CHECK_THROWS_AS(BlockNumOrHash{"invalid"}, std::invalid_argument);
    }
    SECTION("operator<<") {
        std::stringstream out;

        BlockNumOrHash block_num_or_hash1{"0x374f3"};
        out << block_num_or_hash1;
        CHECK(out.str() == "0x374f3");
        out.str("");

        BlockNumOrHash block_num_or_hash2{"0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c"};
        out << block_num_or_hash2;
        CHECK(out.str() == "0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c");
        out.str("");

        BlockNumOrHash block_num_or_hash3{"latest"};
        out << block_num_or_hash3;
        CHECK(out.str() == "latest");
        out.str("");

        BlockNumOrHash block_num_or_hash4{"pending"};
        out << block_num_or_hash4;
        CHECK(out.str() == "pending");
        out.str("");
    }
}

TEST_CASE("create empty block", "[rpc][types][block]") {
    Block b{};
    CHECK(b.full_tx == false);
}

TEST_CASE("check size of EIP-2718 block from RLP", "[rpc][types][block]") {
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
