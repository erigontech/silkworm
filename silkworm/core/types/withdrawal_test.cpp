/*
   Copyright 2022 The Silkworm Authors

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

#include "withdrawal.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/trie/vector_root.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

using namespace evmc::literals;

TEST_CASE("Withdrawals hash") {
    std::vector<Withdrawal> withdrawals{
        {
            .index = 0,
            .validator_index = 0,
            .address = 0x6295ee1b4f6dd65047762f924ecd367c17eabf8f_address,
            .amount = 1,
        }};

    static constexpr auto kEncoder = [](Bytes& to, const Withdrawal& w) { rlp::encode(to, w); };
    CHECK(to_hex(trie::root_hash(withdrawals, kEncoder)) == "82cc6fbe74c41496b382fcdf25216c5af7bdbb5a3929e8f2e61bd6445ab66436");
}

}  // namespace silkworm
