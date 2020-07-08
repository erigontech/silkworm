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

#include "util.hpp"

#include <boost/endian/conversion.hpp>
#include <cstring>

#include "common/util.hpp"

namespace silkworm::db {
std::string storage_key(const evmc::address& address, uint64_t incarnation,
                        const evmc::bytes32& key) {
  std::string res(kAddressLength + 8 + kHashLength, '\0');
  std::memcpy(res.data(), address.bytes, kAddressLength);
  boost::endian::store_big_u64(byte_pointer_cast(res.data() + kAddressLength), ~incarnation);
  std::memcpy(res.data() + kAddressLength + 8, key.bytes, kHashLength);
  return res;
}
}  // namespace silkworm::db
