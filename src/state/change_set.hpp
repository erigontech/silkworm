/*
   Copyright 2020 The Silkworm Authors

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

#ifndef SILKWORM_STATE_CHANGE_SET_H_
#define SILKWORM_STATE_CHANGE_SET_H_

#include <evmc/evmc.hpp>
#include <map>
#include <string>
#include <string_view>

namespace silkworm {

using AccountChanges = std::map<evmc::address, std::string>;

// Turbo-Geth decodeAccountsWithKeyLen
AccountChanges decode_account_changes(std::string_view b);
}  // namespace silkworm

#endif  // SILKWORM_STATE_CHANGE_SET_H_
