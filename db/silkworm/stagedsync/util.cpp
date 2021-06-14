/*
   Copyright 2020 - 2021 The Silkworm Authors

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
#include "util.hpp"
#include <stdexcept>
#include <memory>
#include <silkworm/db/access_layer.hpp>

namespace silkworm::stagedsync {

void check_stagedsync_error(StageResult code) {
    switch (code)
    {
        case StageResult::kStageBadChainSequence:
            throw std::runtime_error("BadChainSequence: Chain is not in order.");
            break;
        case StageResult::kStageInvalidRange:
            throw std::runtime_error("InvalidRange: Starting block is in greater position than ending block.");
            break;
        case StageResult::kStageAborted:
            throw std::runtime_error("Aborted: Stage was aborted.");
            break;
        default:
            break;
    }
}

std::pair<Bytes, Bytes> convert_to_db_format(const Bytes& key, const Bytes& value) {
    if (key.size() == 8) {
        return {value.substr(0, kAddressLength), value.substr(kAddressLength)};
    }
    Bytes db_key(kHashLength + kAddressLength + db::kIncarnationLength, '\0');
    std::memcpy(&db_key[0], &key[8], kAddressLength + db::kIncarnationLength);
    std::memcpy(&db_key[kAddressLength + db::kIncarnationLength], &value[0], kHashLength);
    return {db_key, value.substr(kHashLength)};
}

}  // namespace silkworm::db