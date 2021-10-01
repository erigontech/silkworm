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

#include "util.hpp"

#include <cassert>
#include <memory>
#include <stdexcept>

#include <magic_enum.hpp>

#include <silkworm/db/util.hpp>

namespace silkworm::stagedsync {

void check_stagedsync_error(StageResult code) {
    if (code != StageResult::kSuccess) {
        std::string error{magic_enum::enum_name<StageResult>(code)};
        throw std::runtime_error(error);
    }
}

std::pair<Bytes, Bytes> change_set_to_plain_state_format(const ByteView key, const ByteView value) {
    if (key.size() == 8) {  // AccountChangeSet
        const Bytes address{value.substr(0, kAddressLength)};
        const Bytes previous_value{value.substr(kAddressLength)};
        return {address, previous_value};
    } else {  // StorageChangeSet
        assert(key.length() == 8 + db::kPlainStoragePrefixLength);
        // See db::storage_change_key
        const ByteView address_with_incarnation{key.substr(8)};
        const ByteView location{value.substr(0, kHashLength)};
        Bytes full_key{address_with_incarnation};
        full_key.append(location);
        const Bytes previous_value{value.substr(kHashLength)};
        return {full_key, previous_value};
    }
}

}  // namespace silkworm::stagedsync
