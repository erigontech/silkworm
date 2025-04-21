// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "block_cache.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("check get cache key not present(lock)", "[rpc][commands][block_cache]") {
    BlockCache block_cache(1, true);
    evmc::bytes32 bh1{0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32};

    auto b = block_cache.get(bh1);
    CHECK(!b);
}

TEST_CASE("check get cache key not present(no-lock)", "[rpc][commands][block_cache]") {
    BlockCache block_cache(1, false);
    evmc::bytes32 bh1{0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32};

    auto b = block_cache.get(bh1);
    CHECK(!b);
}

TEST_CASE("insert entry in cache(lock)", "[rpc][commands][block_cache]") {
    evmc::bytes32 bh1{0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32};
    BlockCache block_cache(1, true);
    auto ret_block_option = block_cache.get(bh1);
    CHECK(!ret_block_option);

    auto block1 = std::make_shared<silkworm::BlockWithHash>();
    block_cache.insert(bh1, block1);

    auto ret_block = block_cache.get(bh1);
    CHECK(ret_block->hash == block1->hash);
}

TEST_CASE("insert entry in cache(no-lock)", "[rpc][commands][block_cache]") {
    evmc::bytes32 bh1{0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32};
    BlockCache block_cache(1, false);
    auto ret_block_option = block_cache.get(bh1);
    CHECK(!ret_block_option);

    auto block1 = std::make_shared<silkworm::BlockWithHash>();
    block_cache.insert(bh1, block1);

    auto ret_block = block_cache.get(bh1);
    CHECK(ret_block->hash == block1->hash);
}

}  // namespace silkworm
