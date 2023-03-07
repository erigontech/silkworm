/*
   Copyright 2021 The Silkrpc Authors

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

#include "block_cache.hpp"
#include <catch2/catch.hpp>

namespace silkrpc {

using Catch::Matchers::Message;
using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

TEST_CASE("check get cache key not present(lock)", "[silkrpc][commands][block_cache]") {
    BlockCache block_cache(1, true);
    evmc::bytes32 bh1{0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32};

    auto b = block_cache.get(bh1);
    CHECK(!b);
}

TEST_CASE("check get cache key not present(no-lock)", "[silkrpc][commands][block_cache]") {
    BlockCache block_cache(1, false);
    evmc::bytes32 bh1{0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32};

    auto b = block_cache.get(bh1);
    CHECK(!b);
}

TEST_CASE("insert entry in cache(lock)", "[silkrpc][commands][block_cache]") {
    evmc::bytes32 bh1{0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32};
    BlockCache block_cache(1, true);
    auto ret_block_option = block_cache.get(bh1);
    CHECK(!ret_block_option);

    const silkworm::BlockWithHash block1 {};
    block_cache.insert(bh1, block1);

    ret_block_option = block_cache.get(bh1);
    CHECK((*ret_block_option).hash == block1.hash);
}

TEST_CASE("insert entry in cache(no-lock)", "[silkrpc][commands][block_cache]") {
    evmc::bytes32 bh1{0x374f3a049e006f36f6cf91b02a3b0ee16c858af2f75858733eb0e927b5b7126c_bytes32};
    BlockCache block_cache(1, false);
    auto ret_block_option = block_cache.get(bh1);
    CHECK(!ret_block_option);

    const silkworm::BlockWithHash block1 {};
    block_cache.insert(bh1, block1);

    ret_block_option = block_cache.get(bh1);
    CHECK((*ret_block_option).hash == block1.hash);
}

} // namespace silkrpc

