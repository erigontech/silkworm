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

#include "common/util.hpp"
#include "db/bucket.hpp"

namespace silkworm::state {

std::optional<Account> Reader::read_account(const evmc::address& address) const {
  return db_.get_account(address, block_number_);
}

std::string Reader::read_code(const evmc::bytes32& code_hash) const {
  return db_.get_code(code_hash);
}

evmc::bytes32 Reader::read_storage(const evmc::address& address, uint64_t incarnation,
                                   const evmc::bytes32& key) const {
  return db_.get_storage(address, incarnation, key, block_number_);
}
}  // namespace silkworm::state
