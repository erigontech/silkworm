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

#include "reader.hpp"

// TODO(Andrew) implement

namespace silkworm::state {

std::optional<Account> Reader::read_account(const evmc::address&) const { return {}; }

std::string Reader::read_account_code(const evmc::address&) const { return ""; }

evmc::bytes32 Reader::read_account_storage(const evmc::address&, uint64_t,
                                           const evmc::bytes32&) const {
  return {};
}

}  // namespace silkworm::state
