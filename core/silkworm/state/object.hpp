/*
   Copyright 2020-2021 The Silkworm Authors

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

#ifndef SILKWORM_STATE_OBJECT_HPP_
#define SILKWORM_STATE_OBJECT_HPP_

#include <optional>

#include <silkworm/common/base.hpp>
#include <silkworm/common/hash_maps.hpp>
#include <silkworm/types/account.hpp>

namespace silkworm::state {

struct Object {
    std::optional<Account> initial;
    std::optional<Account> current;
};

struct CommittedValue {
    evmc::bytes32 initial{};   // value at the begining of the block
    evmc::bytes32 original{};  // value at the begining of the transaction; see EIP-2200
};

struct Storage {
    FlatHashMap<evmc::bytes32, CommittedValue> committed;
    FlatHashMap<evmc::bytes32, evmc::bytes32> current;
};

}  // namespace silkworm::state

#endif  // SILKWORM_STATE_OBJECT_HPP_
