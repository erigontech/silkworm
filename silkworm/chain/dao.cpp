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

#include "dao.hpp"

namespace silkworm::dao {

void transfer_balances(IntraBlockState& state) {
    for (const evmc::address& address : kChildren) {
        state.add_to_balance(kWithdraw, state.get_balance(address));
        state.set_balance(address, 0);
    }
}
}  // namespace silkworm::dao
