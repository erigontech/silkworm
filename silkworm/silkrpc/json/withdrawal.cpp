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

#include <cstring>
#include <utility>

#include <silkworm/core/common/util.hpp>

#include "filter.hpp"
#include "types.hpp"

namespace silkworm {

void to_json(nlohmann::json& json, const silkworm::Withdrawal& withdrawal) {
    json["address"] = "0x" + silkworm::to_hex(withdrawal.address);
    json["amount"] = silkworm::rpc::to_quantity(withdrawal.amount);
    json["index"] = silkworm::rpc::to_quantity(withdrawal.index);
    json["validatorIndex"] = silkworm::rpc::to_quantity(withdrawal.validator_index);
}

}  // namespace silkworm
