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

#include "util.hpp"

#include <cstdlib>
#include <cstring>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/db/util.hpp>

namespace silkworm::rpc::ethdb::kv {

silkworm::Bytes composite_storage_key(const evmc::address& address, uint64_t incarnation, HashAsArray hash) {
    silkworm::Bytes res(kAddressLength + db::kIncarnationLength + kHashLength, '\0');
    std::memcpy(&res[0], address.bytes, kAddressLength);
    endian::store_big_u64(&res[kAddressLength], incarnation);
    std::memcpy(&res[kAddressLength + db::kIncarnationLength], hash, kHashLength);
    return res;
}

}  // namespace silkworm::rpc::ethdb::kv
